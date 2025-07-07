const fastifyApp = require('../server');

module.exports = (req, res) => {
  fastifyApp.ready(err => {
    if (err) throw err; 
    fastifyApp.server.emit('request', req, res);
  });
}; 