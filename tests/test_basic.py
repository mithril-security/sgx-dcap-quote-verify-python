import os
from datetime import datetime

import sgx_dcap_quote_verify


def get_content_from_file(path):
    with open(path) as f:
        return f.read()


def get_content_from_binary_file(path):
    with open(path, "rb") as f:
        return f.read()


PATH_TO_SAMPLE_DATA = os.path.join(
    os.path.dirname(__file__),
    "../SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationApp/sampleData/",
)

d = {
    "trusted_root_ca_certificate": get_content_from_file(
        PATH_TO_SAMPLE_DATA + "trustedRootCaCert.pem"
    ),
    "pck_certificate": get_content_from_file(PATH_TO_SAMPLE_DATA + "pckCert.pem"),
    "pck_signing_chain": get_content_from_file(
        PATH_TO_SAMPLE_DATA + "pckSignChain.pem"
    ),
    "root_ca_crl": get_content_from_file(PATH_TO_SAMPLE_DATA + "rootCaCrl.pem"),
    "intermediate_ca_crl": get_content_from_file(
        PATH_TO_SAMPLE_DATA + "intermediateCaCrl.pem"
    ),
    "tcb_info": get_content_from_file(PATH_TO_SAMPLE_DATA + "tcbInfo.json"),
    "tcb_signing_chain": get_content_from_file(
        PATH_TO_SAMPLE_DATA + "tcbSignChain.pem"
    ),
    "quote": get_content_from_binary_file(PATH_TO_SAMPLE_DATA + "quote.dat"),
    "qe_identity": get_content_from_file(PATH_TO_SAMPLE_DATA + "qeIdentity.json"),
    "expiration_date": datetime.now(),
}


def test_verification_passing():
    """
    Valid dummy test quote
    """
    res = sgx_dcap_quote_verify.verify(**d)

    assert res.ok
    assert (
        res.pck_certificate_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    )
    assert res.tcb_info_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.qe_identity_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.quote_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK

    assert res.enclave_report.mr_enclave == 32 * b"\x00"


def test_verification_failure():
    """
    Test case with corrupted quote
    """
    dd = d.copy()
    quote = bytearray(get_content_from_binary_file(PATH_TO_SAMPLE_DATA + "quote.dat"))
    # corrupt the quote
    quote[0:10] = 10 * b"\xff"
    dd["quote"] = bytes(quote)
    res = sgx_dcap_quote_verify.verify(**dd)
    assert not res.ok
    assert (
        res.pck_certificate_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    )
    assert res.tcb_info_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.qe_identity_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert (
        res.quote_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_UNSUPPORTED_QUOTE_FORMAT
    )
    assert res.enclave_report is None


def test_verification_failure2():
    """
    Test case when no trusted root CA is specified
    """
    dd = d.copy()
    dd["trusted_root_ca_certificate"] = ""
    res = sgx_dcap_quote_verify.verify(**dd)

    assert not res.ok
    assert (
        res.pck_certificate_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT
    )
    assert (
        res.tcb_info_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_UNSUPPORTED_CERT_FORMAT
    )
    assert (
        res.qe_identity_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_UNSUPPORTED_CERT_FORMAT
    )
    assert res.quote_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.enclave_report is not None


def test_verification_expired():
    """
    Test case when collateral is not yet valid
    """
    dd = d.copy()
    dd["expiration_date"] = datetime.fromisoformat("2018-01-01")
    res = sgx_dcap_quote_verify.verify(**dd)

    assert not res.ok
    assert (
        res.pck_certificate_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_CRL_EXPIRED
    )
    assert (
        res.tcb_info_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_CRL_EXPIRED
    )
    assert (
        res.qe_identity_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_CRL_EXPIRED
    )
    assert res.quote_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.enclave_report is not None


def test_verification_expired2():
    """
    Test case when collateral has expired
    """
    dd = d.copy()
    dd["expiration_date"] = datetime.fromisoformat("2030-01-01")
    res = sgx_dcap_quote_verify.verify(**dd)

    assert not res.ok
    assert (
        res.pck_certificate_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_PCK_CERT_CHAIN_EXPIRED
    )
    assert (
        res.tcb_info_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED
    )
    assert (
        res.qe_identity_status
        == sgx_dcap_quote_verify.VerificationStatus.STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED
    )
    assert res.quote_status == sgx_dcap_quote_verify.VerificationStatus.STATUS_OK
    assert res.enclave_report is not None
