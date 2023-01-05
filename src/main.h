#ifndef MAIN_H
#define MAIN_H

#include <chrono>
#include <optional>
#include <string>

#include "nlohmann/json.hpp"
#include <pybind11/pybind11.h>

#include "../SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/Quote.h"
#include <SgxEcdsaAttestation/QuoteVerification.h>

namespace py = pybind11;

namespace nlohmann {
template <class T> void to_json(nlohmann::json &j, const std::optional<T> &v) {
    if (v.has_value()) {
        j = *v;
    } else {
        j = nullptr;
    }
}

template <class T>
void from_json(const nlohmann::json &j, std::optional<T> &v) {
    if (j.is_null()) {
        v = std::nullopt;
    } else {
        v = j.get<T>();
    }
}
} // namespace nlohmann

namespace intel::sgx::dcap::quote {
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(EnclaveReport, cpuSvn, miscSelect, reserved1,
                                   attributes, mrEnclave, reserved2, mrSigner,
                                   reserved3, isvProdID, isvSvn, reserved4,
                                   reportData)
}

auto verify(const std::string &trustedRootCACertificate,
            const std::string &pckCertificate,
            const std::string &pckSigningChain, const std::string &rootCaCrl,
            const std::string &intermediateCaCrl, const std::string &tcbInfo,
            const std::string &tcbSigningChain, const py::bytes &quote,
            const std::string &qeIdentity,
            const std::chrono::system_clock::time_point &expirationDate)
    -> py::bytes;

struct VerificationResult {
    bool ok;
    Status pckCertificateStatus;
    Status tcbInfoStatus;
    Status qeIdentityStatus;
    Status quoteStatus;
    std::optional<intel::sgx::dcap::quote::EnclaveReport> enclaveReport;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(VerificationResult, ok, pckCertificateStatus,
                                   tcbInfoStatus, qeIdentityStatus, quoteStatus,
                                   enclaveReport)

static_assert(sizeof(std::time_t) >= sizeof(int64_t),
              "std::time_t size too small, the dates may overflow");

#endif
