/**
 * L'Oreal Beauty Advisor Portal - Frontend Application
 * Version: 3.0.0
 */

document.addEventListener('DOMContentLoaded', function() {
  const alerts = document.querySelectorAll('.alert-dismissible');
  alerts.forEach(function(alert) {
    setTimeout(function() {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 10000);
  });

  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach(function(link) {
    if (link.getAttribute('href') === currentPath) {
      link.classList.add('active');
    }
  });
});
