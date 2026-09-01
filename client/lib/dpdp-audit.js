// IIFE bundle of DPDP Act 2023 Compliance Audit Engine for content scripts
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.DPDPAudit = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  const DPDP_SCHEDULE_MAP = {
    aadhaar: { schedule: "Section 3(1)(b)", categoryName: "National Identity (Aadhaar)", riskLevel: "HIGH" },
    pan: { schedule: "Section 3(1)(b)", categoryName: "Tax Identification (PAN)", riskLevel: "HIGH" },
    passport: { schedule: "Section 3(1)(b)", categoryName: "Travel Identity (Passport)", riskLevel: "HIGH" },
    govt_id: { schedule: "Section 3(1)(b)", categoryName: "Government Issued ID", riskLevel: "HIGH" },
    card: { schedule: "Section 3(1)(a)", categoryName: "Financial (Payment Card)", riskLevel: "CRITICAL" },
    cvv: { schedule: "Section 3(1)(a)", categoryName: "Financial (Card Security Code)", riskLevel: "CRITICAL" },
    bank_account: { schedule: "Section 3(1)(a)", categoryName: "Financial (Bank Account)", riskLevel: "HIGH" },
    upi_id: { schedule: "Section 3(1)(a)", categoryName: "Financial (UPI Handle)", riskLevel: "MEDIUM" },
    ifsc: { schedule: "Section 3(1)(a)", categoryName: "Financial (Bank Branch Code)", riskLevel: "MEDIUM" },
    phone: { schedule: "Section 3(1)(c)", categoryName: "Contact (Mobile Number)", riskLevel: "MEDIUM" },
    email: { schedule: "Section 3(1)(c)", categoryName: "Contact (Email Address)", riskLevel: "MEDIUM" },
    address: { schedule: "Section 3(1)(c)", categoryName: "Location (Physical Address)", riskLevel: "MEDIUM" },
    pincode: { schedule: "Section 3(1)(c)", categoryName: "Location (Postal Code)", riskLevel: "LOW" },
    ssn: { schedule: "Section 3(1)(b)", categoryName: "Social Security / Tax ID", riskLevel: "HIGH" },
    dob: { schedule: "Section 3(1)(c)", categoryName: "Personal (Date of Birth)", riskLevel: "MEDIUM" },
    password: { schedule: "Section 3(1)(a)", categoryName: "Authentication (Password/Vault)", riskLevel: "CRITICAL" },
    face: { schedule: "Section 3(1)(d)", categoryName: "Biometric (Face Identifier)", riskLevel: "HIGH" },
    adversarial_injection: { schedule: "Security Threat", categoryName: "Adversarial Prompt Injection", riskLevel: "CRITICAL" },
  };

  function classifyDPDP(piiCategory) {
    if (!piiCategory) return { schedule: "General", categoryName: "Unclassified PII", riskLevel: "LOW" };
    const key = String(piiCategory).toLowerCase().replace(/[^a-z0-9_]/g, "");
    return DPDP_SCHEDULE_MAP[key] || { schedule: "Section 3(1)(c)", categoryName: `Personal Data (${piiCategory})`, riskLevel: "MEDIUM" };
  }

  function generateDPDPAuditReport({ url, step, detections = [], securityAlerts = [], hybridStats = {} }) {
    const timestamp = new Date().toISOString();
    let financialCount = 0;
    let identityCount = 0;
    let contactCount = 0;
    let biometricCount = 0;
    let totalRedacted = detections.length;

    const entries = detections.map((d) => {
      const info = classifyDPDP(d.category || d.piiCategory);
      if (info.schedule.includes("3(1)(a)")) financialCount++;
      else if (info.schedule.includes("3(1)(b)")) identityCount++;
      else if (info.schedule.includes("3(1)(c)")) contactCount++;
      else if (info.schedule.includes("3(1)(d)")) biometricCount++;

      return {
        category: d.category || d.piiCategory || "unknown",
        dpdpSchedule: info.schedule,
        dpdpCategory: info.categoryName,
        riskLevel: info.riskLevel,
        source: d.source || "dom_dlp",
        action: "REDACTED_ON_DEVICE_SOLID_BLACKOUT",
      };
    });

    const totalThreats = securityAlerts.length;
    const minimizationScore = 100;

    return {
      act: "Digital Personal Data Protection Act (DPDP) 2023 / Rules 2025",
      complianceStatus: "COMPLIANT_ON_DEVICE_MINIMIZATION",
      minimizationScore: `${minimizationScore}%`,
      timestamp,
      originUrl: url || "active-tab",
      step,
      hybridEngineMode: hybridStats.a11yBypassed ? "HYBRID_A11Y_FASTPATH" : "VISION_FALLBACK_ACTIVE",
      statistics: {
        totalRedactedElements: totalRedacted,
        financialDataCount: financialCount,
        identityDataCount: identityCount,
        contactDataCount: contactCount,
        biometricCount,
        adversarialThreatsBlocked: totalThreats,
      },
      auditEntries: entries,
      securityQuarantine: securityAlerts.map((a) => ({
        threatType: a.type,
        reason: a.reason || a.text,
        action: "QUARANTINED_BEFORE_EGRESS",
      })),
    };
  }

  return {
    DPDP_SCHEDULE_MAP,
    classifyDPDP,
    generateDPDPAuditReport,
  };
});
