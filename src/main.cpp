#include <pybind11/chrono.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/Quote.h"
#include "AttestationLibraryAdapter.h"

#include "main.h"

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

namespace py = pybind11;
using json = nlohmann::json;

auto verify(const std::string &trustedRootCACertificate,
            const std::string &pckCertificate,
            const std::string &pckSigningChain, const std::string &rootCaCrl,
            const std::string &intermediateCaCrl, const std::string &tcbInfo,
            const std::string &tcbSigningChain, const py::bytes &quote,
            const std::string &qeIdentity,
            const std::chrono::system_clock::time_point &expirationDate)
    -> py::bytes {
    // pybind11 does not offer a nice way to pass raw bytes with builtin
    // conversion This function gets the quote as a pybind11::bytes and we need
    // to convert it to a vector<uint8_t> for our usecase

    // SAFETY: quote_sv is only valid as long as the corresponding `quote`
    // instance remains alive and so should not outlive the lifetime of the
    // `quote` instance. This is safe here because the string_view content is
    // immediately copied to a vector
    std::string_view sv_raw_quote{quote};
    std::vector<uint8_t> vector_raw_quote(sv_raw_quote.begin(),
                                          sv_raw_quote.end());

    std::shared_ptr<intel::sgx::dcap::AttestationLibraryAdapter>
        attestationLib =
            std::make_shared<intel::sgx::dcap::AttestationLibraryAdapter>();
    std::time_t time_tExpirationDate =
        std::chrono::system_clock::to_time_t(expirationDate);

    const auto pckCertChain = pckSigningChain + pckCertificate;
    const auto pckVerifyStatus = attestationLib->verifyPCKCertificate(
        pckCertChain, rootCaCrl, intermediateCaCrl, trustedRootCACertificate,
        time_tExpirationDate);
    const auto tcbVerifyStatus = attestationLib->verifyTCBInfo(
        tcbInfo, tcbSigningChain, rootCaCrl, trustedRootCACertificate,
        time_tExpirationDate);

    Status qeIdentityVerifyStatus = STATUS_SGX_QE_IDENTITY_INVALID;
    if (!qeIdentity.empty()) {
        qeIdentityVerifyStatus = attestationLib->verifyQeIdentity(
            qeIdentity, tcbSigningChain, rootCaCrl, trustedRootCACertificate,
            time_tExpirationDate);
    }

    const auto quoteVerifyStatus =
        attestationLib->verifyQuote(vector_raw_quote, pckCertificate,
                                    intermediateCaCrl, tcbInfo, qeIdentity);

    intel::sgx::dcap::Quote quote_data;
    std::optional<intel::sgx::dcap::quote::EnclaveReport> enclave_report{};
    if (quote_data.parse(vector_raw_quote) && quote_data.validate()) {
        enclave_report = quote_data.getEnclaveReport();
    }

    std::vector<uint8_t> j = json::to_cbor(json(VerificationResult{
        .ok = pckVerifyStatus == STATUS_OK && tcbVerifyStatus == STATUS_OK &&
              quoteVerifyStatus == STATUS_OK &&
              qeIdentityVerifyStatus == STATUS_OK,
        .pckCertificateStatus = pckVerifyStatus,
        .tcbInfoStatus = tcbVerifyStatus,
        .qeIdentityStatus = qeIdentityVerifyStatus,
        .quoteStatus = quoteVerifyStatus,
        .enclaveReport = enclave_report}));

    return py::bytes(reinterpret_cast<char *>(j.data()), j.size());
}

PYBIND11_MODULE(_core, m) {
    m.def("verify", &verify, py::arg("trusted_root_ca_certificate"),
          py::arg("pck_certificate"), py::arg("pck_signing_chain"),
          py::arg("root_ca_crl"), py::arg("intermediate_ca_crl"),
          py::arg("tcb_info"), py::arg("tcb_signing_chain"), py::arg("quote"),
          py::arg("qe_identity"), py::arg("expiration_date"));

    py::enum_<Status>(m, "VerificationStatus")
        .value("STATUS_OK", STATUS_OK)

        .value("STATUS_UNSUPPORTED_CERT_FORMAT", STATUS_UNSUPPORTED_CERT_FORMAT)
        .value("STATUS_SGX_ROOT_CA_MISSING", STATUS_SGX_ROOT_CA_MISSING)
        .value("STATUS_SGX_ROOT_CA_INVALID", STATUS_SGX_ROOT_CA_INVALID)
        .value("STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS",
               STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS)
        .value("STATUS_SGX_ROOT_CA_INVALID_ISSUER",
               STATUS_SGX_ROOT_CA_INVALID_ISSUER)
        .value("STATUS_SGX_ROOT_CA_UNTRUSTED", STATUS_SGX_ROOT_CA_UNTRUSTED)

        .value("STATUS_SGX_INTERMEDIATE_CA_MISSING",
               STATUS_SGX_INTERMEDIATE_CA_MISSING)
        .value("STATUS_SGX_INTERMEDIATE_CA_INVALID",
               STATUS_SGX_INTERMEDIATE_CA_INVALID)
        .value("STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS",
               STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS)
        .value("STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER",
               STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER)
        .value("STATUS_SGX_INTERMEDIATE_CA_REVOKED",
               STATUS_SGX_INTERMEDIATE_CA_REVOKED)

        .value("STATUS_SGX_PCK_MISSING", STATUS_SGX_PCK_MISSING)
        .value("STATUS_SGX_PCK_INVALID", STATUS_SGX_PCK_INVALID)
        .value("STATUS_SGX_PCK_INVALID_EXTENSIONS",
               STATUS_SGX_PCK_INVALID_EXTENSIONS)
        .value("STATUS_SGX_PCK_INVALID_ISSUER", STATUS_SGX_PCK_INVALID_ISSUER)
        .value("STATUS_SGX_PCK_REVOKED", STATUS_SGX_PCK_REVOKED)

        .value("STATUS_TRUSTED_ROOT_CA_INVALID", STATUS_TRUSTED_ROOT_CA_INVALID)
        .value("STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED",
               STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED)

        .value("STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT",
               STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_TCB_INFO_INVALID", STATUS_SGX_TCB_INFO_INVALID)
        .value("STATUS_TCB_INFO_INVALID_SIGNATURE",
               STATUS_TCB_INFO_INVALID_SIGNATURE)

        .value("STATUS_SGX_TCB_SIGNING_CERT_MISSING",
               STATUS_SGX_TCB_SIGNING_CERT_MISSING)
        .value("STATUS_SGX_TCB_SIGNING_CERT_INVALID",
               STATUS_SGX_TCB_SIGNING_CERT_INVALID)
        .value("STATUS_SGX_TCB_SIGNING_CERT_INVALID_EXTENSIONS",
               STATUS_SGX_TCB_SIGNING_CERT_INVALID_EXTENSIONS)
        .value("STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER",
               STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER)
        .value("STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED",
               STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED)
        .value("STATUS_SGX_TCB_SIGNING_CERT_REVOKED",
               STATUS_SGX_TCB_SIGNING_CERT_REVOKED)

        .value("STATUS_SGX_CRL_UNSUPPORTED_FORMAT",
               STATUS_SGX_CRL_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_CRL_UNKNOWN_ISSUER", STATUS_SGX_CRL_UNKNOWN_ISSUER)
        .value("STATUS_SGX_CRL_INVALID", STATUS_SGX_CRL_INVALID)
        .value("STATUS_SGX_CRL_INVALID_EXTENSIONS",
               STATUS_SGX_CRL_INVALID_EXTENSIONS)
        .value("STATUS_SGX_CRL_INVALID_SIGNATURE",
               STATUS_SGX_CRL_INVALID_SIGNATURE)

        .value("STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT",
               STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_CA_CERT_INVALID", STATUS_SGX_CA_CERT_INVALID)
        .value("STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT",
               STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT)

        .value("STATUS_MISSING_PARAMETERS", STATUS_MISSING_PARAMETERS)

        .value("STATUS_UNSUPPORTED_QUOTE_FORMAT",
               STATUS_UNSUPPORTED_QUOTE_FORMAT)
        .value("STATUS_UNSUPPORTED_PCK_CERT_FORMAT",
               STATUS_UNSUPPORTED_PCK_CERT_FORMAT)
        .value("STATUS_INVALID_PCK_CERT", STATUS_INVALID_PCK_CERT)
        .value("STATUS_UNSUPPORTED_PCK_RL_FORMAT",
               STATUS_UNSUPPORTED_PCK_RL_FORMAT)
        .value("STATUS_INVALID_PCK_CRL", STATUS_INVALID_PCK_CRL)
        .value("STATUS_UNSUPPORTED_TCB_INFO_FORMAT",
               STATUS_UNSUPPORTED_TCB_INFO_FORMAT)
        .value("STATUS_PCK_REVOKED", STATUS_PCK_REVOKED)
        .value("STATUS_TCB_INFO_MISMATCH", STATUS_TCB_INFO_MISMATCH)
        .value("STATUS_TCB_OUT_OF_DATE", STATUS_TCB_OUT_OF_DATE)
        .value("STATUS_TCB_REVOKED", STATUS_TCB_REVOKED)
        .value("STATUS_TCB_CONFIGURATION_NEEDED",
               STATUS_TCB_CONFIGURATION_NEEDED)
        .value("STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED",
               STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED)
        .value("STATUS_TCB_NOT_SUPPORTED", STATUS_TCB_NOT_SUPPORTED)
        .value("STATUS_TCB_UNRECOGNIZED_STATUS", STATUS_TCB_UNRECOGNIZED_STATUS)
        .value("STATUS_UNSUPPORTED_QE_CERTIFICATION",
               STATUS_UNSUPPORTED_QE_CERTIFICATION)
        .value("STATUS_INVALID_QE_CERTIFICATION_DATA_SIZE",
               STATUS_INVALID_QE_CERTIFICATION_DATA_SIZE)
        .value("STATUS_UNSUPPORTED_QE_CERTIFICATION_DATA_TYPE",
               STATUS_UNSUPPORTED_QE_CERTIFICATION_DATA_TYPE)
        .value("STATUS_PCK_CERT_MISMATCH", STATUS_PCK_CERT_MISMATCH)
        .value("STATUS_INVALID_QE_REPORT_SIGNATURE",
               STATUS_INVALID_QE_REPORT_SIGNATURE)
        .value("STATUS_INVALID_QE_REPORT_DATA", STATUS_INVALID_QE_REPORT_DATA)
        .value("STATUS_INVALID_QUOTE_SIGNATURE", STATUS_INVALID_QUOTE_SIGNATURE)

        .value("STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT",
               STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_QE_IDENTITY_INVALID", STATUS_SGX_QE_IDENTITY_INVALID)
        .value("STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE",
               STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE)

        .value("STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT",
               STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT",
               STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_INVALID",
               STATUS_SGX_ENCLAVE_IDENTITY_INVALID)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION",
               STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE",
               STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE)
        .value("STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH",
               STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH)
        .value("STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH",
               STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH)
        .value("STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH",
               STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH)
        .value("STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH",
               STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH)
        .value("STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH",
               STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH)
        .value("STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE",
               STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE)

        .value("STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT",
               STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT)
        .value("STATUS_QE_IDENTITY_OUT_OF_DATE", STATUS_QE_IDENTITY_OUT_OF_DATE)
        .value("STATUS_QE_IDENTITY_MISMATCH", STATUS_QE_IDENTITY_MISMATCH)
        .value("STATUS_SGX_TCB_INFO_EXPIRED", STATUS_SGX_TCB_INFO_EXPIRED)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_INVALID_SIGNATURE",
               STATUS_SGX_ENCLAVE_IDENTITY_INVALID_SIGNATURE)
        .value("STATUS_INVALID_PARAMETER", STATUS_INVALID_PARAMETER)
        .value("STATUS_SGX_PCK_CERT_CHAIN_EXPIRED",
               STATUS_SGX_PCK_CERT_CHAIN_EXPIRED)
        .value("STATUS_SGX_CRL_EXPIRED", STATUS_SGX_CRL_EXPIRED)
        .value("STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED",
               STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED)
        .value("STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED",
               STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED)
        .value("STATUS_TCB_SW_HARDENING_NEEDED", STATUS_TCB_SW_HARDENING_NEEDED)
        .value("STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED",
               STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
        .value("STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED",
               STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED)
        .value("STATUS_TDX_MODULE_MISMATCH", STATUS_TDX_MODULE_MISMATCH);
}
