const jwt = require('jsonwebtoken');
// auth.js file updated as per the refernce from 21-MERN\01-Activities\25-Ins_Resolver-Context\server\utils\auth.js

// set token secret and expiration date
const secret = process.env.JWT_SECRET;
const expiration = '2h';

module.exports = {
  // function for our authenticated routes
  authMiddleware: function (req) {
    // allows token to be sent via req.body, req.query or headers
    let token = req.query.token || req.body.token ||req.headers.authorization;
// we split the token string into an array and retrun actual token
    // ["Bearer", "<tokenvalue>"]
    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    if (!token) {
      return req;
    }

    // verify token and get user data out of it
    // if token can be verified, add the decoded user's data to the request so it can be accessed in the resolver
    try {
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
    } catch {
      console.log('Invalid token');
   }

    // send to next endpoint
    // return the request object so it can be passed to the resolver as `context`
    return req;
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};
