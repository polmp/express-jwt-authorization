const UnauthorizedError = require('./error');

function JWTAuthorization(permissions, options) {
  const defaults = {
    roleParameter: 'role',
    userParameter: 'user',
  };
  this.options = Object.assign(defaults, options);
  this.permissions = permissions;
  
  this._getDecodedPayload = function(req) {
    let decodedPayload;
    if (typeof this.options.getDecodedPayload === 'function') {
      decodedPayload = this.options.getDecodedPayload(req);
    } else {
      decodedPayload = req[this.options.userParameter];
    }

    if (decodedPayload === null) {
      throw new UnauthorizedError(
        'token_not_specified',
        'Token is not specified',
      );
    }
    return decodedPayload;
  };

  this._setDecodedPayload = function(req) {
    let decodedPayload;
    try {
      decodedPayload = this._getDecodedPayload(req);
    } catch (err) {
      throw err;
    }

    if (typeof decodedPayload === 'undefined') return;

    const userRole = decodedPayload[this.options.roleParameter];
    if (typeof userRole === 'undefined')
      throw new UnauthorizedError(
        'missing_field',
        `'${
          this.options.roleParameter
        }' field not defined in the decoded payload`,
      );

    if (this._userObjNotInReq(req))
      req[this.options.userParameter] = decodedPayload;
  };

  this._userObjNotInReq = function(req) {
    return Object.is(req[this.options.userParameter], undefined);
  };

  this.isAuth = (req, role) => {
    if (typeof req === 'undefined')
      throw new UnauthorizedError(
        'missing_parameter',
        'Missing request parameter',
      );
    if (typeof role === 'undefined')
      throw new UnauthorizedError(
        'missing_parameter',
        'Missing role parameter',
      );

    if (req[this.options.userParameter])
      return (
        req[this.options.userParameter][this.options.roleParameter] === role
      );

    return false;
  };
}

JWTAuthorization.prototype.checkRole = function(role) {
  return function(req, res, next) {
    try {
      this._setDecodedPayload(req);
    } catch (err) {
      return next(err);
    }

    const decodedPayload = req[this.options.userParameter];
    if (typeof decodedPayload === 'undefined')
      throw new UnauthorizedError(
        'undefined_payload',
        'Payload is not defined',
      );

    const userRole = decodedPayload[this.options.roleParameter];

    if (userRole === role) {
      return next();
    } else {
      return next(
        new UnauthorizedError(
          'role_not_allowed',
          'Your role is not allowed to perform this action',
        ),
      );
    }
  }.bind(this);
};

JWTAuthorization.prototype.decode = function() {
  return function(req, res, next) {
    try {
      this._setDecodedPayload(req);
    } catch (err) {
      return next(err);
    }
    return next();
  }.bind(this);
};

JWTAuthorization.prototype.checkPermission = function(requestedPermissions) {
  if (
    requestedPermissions.constructor !== Array &&
    requestedPermissions.constructor !== String
  ) {
    throw new UnauthorizedError(
      'incorrect_format',
      'Permission needs to be an array or a string',
    );
  }

  if (requestedPermissions.constructor === String) {
    requestedPermissions = requestedPermissions.split(' ');
  }

  const processArray = (permissions, rolePermissions) => {
    return permissions.every(permission => {
      return rolePermissions.includes(permission);
    });
  };

  return function(req, res, next) {
    try {
      this._setDecodedPayload(req);
    } catch (err) {
      return next(err);
    }
    const decodedPayload = req[this.options.userParameter];
    if (typeof decodedPayload === 'undefined')
      throw new UnauthorizedError(
        'undefined_payload',
        'Payload is not defined',
      );
    const userRole =decodedPayload[this.options.roleParameter];
    const rolePermissions = this.permissions[userRole];
    const result = requestedPermissions.some(permission => {
      if (permission.constructor === String)
        return processArray(requestedPermissions, rolePermissions);
      return processArray(permission, rolePermissions);
    });
    if (result) {
      return next();
    } else {
      return next(
        new UnauthorizedError(
          'permission_not_allowed',
          'You are not allowed to perform this action',
        ),
      );
    }
  }.bind(this);
};

module.exports = JWTAuthorization;
