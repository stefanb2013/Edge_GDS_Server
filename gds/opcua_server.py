"""Builds and configures the asyncua OPC UA server exposing the *real* OPC
UA Part 12 GDS information model, imported from the official
`Opc.Ua.Gds.NodeSet2.xml` (vendored under nodesets/, MIT-licensed by the OPC
Foundation) rather than hand-built -- see gds_methods.py for what each
method does, and README.md for the one known asyncua encoding bug this
module works around.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from asyncua import Server, ua
from asyncua.common.ua_utils import get_node_subtypes

from gds import pki
from gds.config import Settings
from gds.gds_methods import GdsContext, build_handlers, build_trust_list_file_handlers

logger = logging.getLogger(__name__)

GDS_NAMESPACE_URI = "http://opcfoundation.org/UA/GDS/"
OWN_IDS_NAMESPACE_URI = "http://example.org/GDS/ids/"
GDS_NODESET_PATH = Path(__file__).resolve().parent.parent / "nodesets" / "Opc.Ua.Gds.NodeSet2.xml"

DIRECTORY_METHOD_NAMES = [
    "RegisterApplication", "UnregisterApplication", "FindApplications",
    "GetCertificateGroups", "GetTrustList", "StartSigningRequest",
    "StartNewKeyPairRequest", "FinishRequest", "GetCertificateStatus",
    "RevokeCertificate",
]
CERTIFICATE_GROUP_BROWSE_NAMES = ["DefaultApplicationGroup", "DefaultHttpsGroup", "DefaultUserTokenGroup"]
TRUST_LIST_METHOD_NAMES = ["Open", "OpenWithMasks", "Read", "GetPosition", "Close"]


def _unwrap_variants(handler: Callable) -> Callable:
    """asyncua passes raw ua.Variant objects as method call arguments (see
    MethodService._call in asyncua/server/address_space.py); our handlers in
    gds_methods.py are written against plain python/ua values for
    readability, so unwrap here once at binding time.
    """

    async def wrapper(parent, *variants):
        values = [v.Value if isinstance(v, ua.Variant) else v for v in variants]
        return await handler(parent, *values)

    return wrapper


async def fix_null_extension_object_encodings(server_or_client) -> None:
    """Works around a real asyncua 2.0.1 bug: structures declared only via
    `DataTypeDefinition` (no separate "Default Binary" encoding object) --
    as `ApplicationRecordDataType` is in the official GDS nodeset -- get
    dynamically registered by asyncua.common.structures104 with a *null*
    NodeId(0,0) as their binary-encoding id, instead of one that actually
    resolves. Per the OPC UA 1.04+ convention for such structures, the
    DataType's own NodeId doubles as its binary encoding id.

    The affected registries (`ua.typeid_by_extension_objects` and friends)
    are process-global on the `asyncua.ua` module, independent of whether
    *this* process is acting as a server or a client -- so this same
    function fixes either side; call it after `server.import_xml(...)` /
    `client.load_data_type_definitions()` respectively. A real (non-asyncua)
    GDS client, e.g. a PLC's own vendor stack, never hits this bug at all;
    this only matters for asyncua-based servers and test/verification
    clients talking to each other.

    Fixed up by BrowseName lookup among Structure's subtypes (not a
    hardcoded NodeId), so this keeps working if a future nodeset revision
    introduces more such structures. Confirmed empirically (see README) that
    exactly one type -- ApplicationRecordDataType -- is affected as of the
    current nodeset + asyncua 2.0.1.
    """
    null_id = ua.NodeId(0, 0)
    broken = [cls for cls, tid in ua.typeid_by_extension_objects.items() if tid == null_id]
    if not broken:
        return

    structure_type_node = server_or_client.get_node(ua.NodeId(ua.ObjectIds.Structure, 0))
    subtype_nodes = await get_node_subtypes(structure_type_node)
    by_name = {}
    for node in subtype_nodes:
        bn = await node.read_browse_name()
        by_name[bn.Name] = node.nodeid

    for cls in broken:
        nodeid = by_name.get(cls.__name__)
        if nodeid is None:
            logger.warning(
                "Could not resolve a real binary-encoding NodeId for %s; "
                "ExtensionObjects of this type will fail to encode.", cls.__name__,
            )
            continue
        ua.typeid_by_extension_objects[cls] = nodeid
        ua.extension_objects_by_typeid[nodeid] = cls
        logger.info("Fixed null ExtensionObject encoding for %s -> %s", cls.__name__, nodeid)


async def _ensure_own_instance_certificate(server: Server, settings: Settings) -> str:
    """The GDS's own OPC UA endpoint needs an application instance
    certificate to offer Sign/SignAndEncrypt security policies. Self-signed
    on first boot and reused after that.
    """
    # asyncua infers PEM vs. DER from the file extension, so use .pem explicitly.
    key_path = settings.opcua_own_cert_dir / "server_key.pem"
    cert_path = settings.opcua_own_cert_dir / "server_cert.pem"
    application_uri = f"urn:{settings.hostname}:GDS:Server"

    if not (key_path.exists() and cert_path.exists()):
        key_pem, cert_pem = pki.generate_self_signed_app_cert(
            application_uri=application_uri,
            common_name="Edge GDS Server",
            hostname=settings.hostname,
            valid_days=3650,
        )
        key_path.write_text(key_pem)
        cert_path.write_text(cert_pem)
        logger.info("Generated self-signed OPC UA instance certificate at %s", cert_path)

    await server.set_application_uri(application_uri)
    await server.load_certificate(str(cert_path))
    await server.load_private_key(str(key_path))
    return application_uri


async def _bind_directory_methods(server: Server, gds_idx: int, ctx: GdsContext) -> ua.Node:
    handlers = build_handlers(ctx)
    directory = await server.get_objects_node().get_child(f"{gds_idx}:Directory")
    for name in DIRECTORY_METHOD_NAMES:
        method_node = await directory.get_child(f"{gds_idx}:{name}")
        server.iserver.isession.add_method_callback(method_node.nodeid, _unwrap_variants(handlers[name]))
    return directory


async def _bind_certificate_groups(server: Server, gds_idx: int, directory: ua.Node, ctx: GdsContext) -> None:
    file_handlers = build_trust_list_file_handlers(ctx)
    cert_groups = await directory.get_child(f"{gds_idx}:CertificateGroups")

    for group_name in CERTIFICATE_GROUP_BROWSE_NAMES:
        try:
            group_node = await cert_groups.get_child(f"0:{group_name}")
        except ua.uaerrors.UaStatusCodeError:
            continue
        trust_list_node = await group_node.get_child("0:TrustList")
        ctx.trust_list_nodeids.append(trust_list_node.nodeid)
        for name in TRUST_LIST_METHOD_NAMES:
            method_node = await trust_list_node.get_child(f"0:{name}")
            server.iserver.isession.add_method_callback(method_node.nodeid, _unwrap_variants(file_handlers[name]))
        if group_name == "DefaultApplicationGroup":
            ctx.default_group_nodeid = group_node.nodeid


async def build_address_space(server: Server, ctx: GdsContext) -> None:
    await server.import_xml(str(GDS_NODESET_PATH))
    await fix_null_extension_object_encodings(server)

    gds_idx = await server.get_namespace_index(GDS_NAMESPACE_URI)
    ctx.own_ids_ns = await server.register_namespace(OWN_IDS_NAMESPACE_URI)

    directory = await _bind_directory_methods(server, gds_idx, ctx)
    await _bind_certificate_groups(server, gds_idx, directory, ctx)

    if ctx.default_group_nodeid is None or not ctx.trust_list_nodeids:
        raise RuntimeError(
            "GDS nodeset import did not produce the expected CertificateGroups/"
            "DefaultApplicationGroup/TrustList nodes -- check nodesets/Opc.Ua.Gds.NodeSet2.xml"
        )


async def create_server(ctx: GdsContext) -> Server:
    settings = ctx.settings
    server = Server()
    await server.init()
    server.set_endpoint(settings.opcua_endpoint)
    server.set_server_name("Edge GDS Server")

    await _ensure_own_instance_certificate(server, settings)
    server.set_security_policy([
        ua.SecurityPolicyType.NoSecurity,
        ua.SecurityPolicyType.Basic256Sha256_Sign,
        ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
    ])

    await build_address_space(server, ctx)
    return server
