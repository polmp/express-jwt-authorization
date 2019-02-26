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

    if (decodedPayload === undefined) {
      throw new Error('Payload is not defined');
    }
    return decodedPayload;
  };
}

JWTAuthorization.prototype.checkRole = function(role) {
  return function(req, res, next) {
    let userPayload;
    try {
      userPayload = this._getDecodedPayload(req);
    } catch (err) {
      return next(err);
    }
    const userRole = userPayload[this.options.roleParameter];
    if (userRole === undefined)
      return next(
        new Error(
          `'${
            this.options.roleParameter
          }' field not defined in the decoded payload`,
        ),
      );
    next(
      userRole === role
        ? void 0
        : new UnauthorizedError(
            'role_not_allowed',
            'Your role is not allowed to perform this action',
          ),
    );
  }.bind(this);
};

JWTAuthorization.prototype.checkPermission = function(requestedPermissions) {
  if (
    requestedPermissions.constructor !== Array &&
    requestedPermissions.constructor !== String
  ) {
    throw new Error('Permission needs to be an array or a string');
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
    let userPayload;
    try {
      userPayload = this._getDecodedPayload(req);
    } catch (err) {
      return next(err);
    }
    const userRole = userPayload[this.options.roleParameter];
    const rolePermissions = this.permissions[userRole];
    const result = requestedPermissions.some(permission => {
      if (permission.constructor === String)
        return processArray(requestedPermissions, rolePermissions);
      return processArray(permission, rolePermissions);
    });
    next(
      result
        ? void 0
        : new UnauthorizedError(
            'permission_not_allowed',
            'You are not allowed to perform this action',
          ),
    );
  }.bind(this);
};

module.exports = JWTAuthorization;
