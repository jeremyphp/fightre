// Intentionally leaky sample bundle for `fightre audit examples/leaky-dist`.
// Everything in this file is fake and exists to trigger an audit finding.
(function () {
  var API_BASE = "https://internal-billing.svc.internal:8443/v1";
  var api_key = "sk_live_51H8xQ2eZvKYlo2C9EXAMPLE1234";

  function chargeCustomer(id) {
    return fetch(API_BASE + "/charges", {
      method: "POST",
      headers: { "authorization": "Bearer " + api_key },
      body: JSON.stringify({ customer: id })
    });
  }

  window.chargeCustomer = chargeCustomer;
})();
//# sourceMappingURL=app.js.map
