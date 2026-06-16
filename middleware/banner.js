// FIXED: Remove verbose server banner (information disclosure)
module.exports = function(req, res, next) {
  // FIX: Use a generic server header instead of revealing the full tech stack
  res.setHeader('Server', 'Web Server');
  next();
};
