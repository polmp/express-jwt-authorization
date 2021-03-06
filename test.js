const AuthorizationJWT = require('./index');

const samplePermissions = {
  admin: [
    'recoverPassword',
    'generateToken',
    'changePassword',
    'changeEmail',
    'deleteUser',
    'getUserData',
  ],
  user: ['recoverPassword', 'changePassword', 'changeEmail'],
};

// Simulate req and res objects
const res = {};
let req = { user: { role: 'user' } };
const middleware = (err, _req, _res, _next) => {
  if (err) throw err;
};

let authorization;

test('Check if roleParameter option works correctly', () => {
  authorization = new AuthorizationJWT(samplePermissions, {
    roleParameter: 'assigned_role',
  });
  try {
    authorization.checkRole('admin')(req, res, middleware);
  } catch (err) {
    expect(err.message).toBe(
      `'assigned_role' field not defined in the decoded payload`,
    );
  }
});

test('Check if userParameter option works correctly', () => {
  authorization = new AuthorizationJWT(samplePermissions, {
    userParameter: 'custom_user',
  });
  try {
    authorization.checkRole('admin')(req, res, middleware);
  } catch (err) {
    expect(err.message).toBe('Payload is not defined');
  }
});

test('Test getDecodedToken function', () => {
  req = {}; // Set for allowing to edit by reference
  const getDecodedPayload = req => ({ id: '1', role: 'admin' });
  authorization = new AuthorizationJWT(samplePermissions, {getDecodedPayload});
  expect(
    authorization.checkRole('admin')(req, res, middleware),
  ).toBeUndefined();
});

test('Test getDecodedToken function (expect fail)', () => {
  req = {};
  const getDecodedPayload = req => ({ id: '1', role: 'admin' });
  authorization = new AuthorizationJWT(samplePermissions, {
    getDecodedPayload,
  });
  try {
    authorization.checkRole('client')(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('role_not_allowed');
  }
});

test('Is a role allowed to access a resource check by role (expect fail)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkRole('admin')(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('role_not_allowed');
  }
});

test('Is a role allowed to access a resource check by role (expect success)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  authorization.checkRole('admin')(
    { user: { role: 'admin' } },
    res,
    middleware,
  );
});

test('Is a role allowed to access a specific permission (expect fail)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkPermission('generateToken')(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('permission_not_allowed');
  }
});

test('Check if different user input fail in checking permissions', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkPermission(['generateToken'])(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('permission_not_allowed');
  }
});

test('Test chaining permissions (and) (expect fail)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkPermission(['recoverPassword', 'generateToken'])(
      req,
      res,
      middleware,
    );
  } catch (err) {
    expect(err.code).toBe('permission_not_allowed');
  }
});

test('Test chaining permissions (and) (expect success)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  expect(
    authorization.checkPermission([['recoverPassword', 'changePassword']])(
      req,
      res,
      middleware,
    ),
  ).toBeUndefined();
});

test('Test chaining permissions (or) (expect success)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  expect(
    authorization.checkPermission([['recoverPassword'], ['generateToken']])(
      req,
      res,
      middleware,
    ),
  ).toBeUndefined();
});

test('Test chaining permissions (or) (expect fail)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkPermission([
      ['deleteUser'],
      ['generateToken'],
      ['getUserData'],
    ])(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('permission_not_allowed');
  }
});

test('Test chaining permissions using and/or (expect fail)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  try {
    authorization.checkPermission([
      ['deleteUser', 'recoverPassword'],
      ['changePassword', 'generateToken'],
    ])(req, res, middleware);
  } catch (err) {
    expect(err.code).toBe('permission_not_allowed');
  }
});

test('Test chaining permissions using and/or (expect success)', () => {
  authorization = new AuthorizationJWT(samplePermissions);
  expect(
    authorization.checkPermission([
      ['deleteUser', 'recoverPassword'],
      ['changePassword', 'changeEmail'],
    ])(req, res, middleware),
  ).toBeUndefined();
});

test('Decode without setting a payload', () => {
  const middleware = (err)=>{
    expect(err).toBeUndefined();
  };
  req = {};
  authorization = new AuthorizationJWT(samplePermissions, {});
  authorization.decode()(req,res,middleware);
});

test('Decode middleware', () => {
  const getDecodedPayload = req => ({ id: '5', role: 'user' });
  const middleware = (err)=>{
    expect(err).toBeUndefined();
  };
  req = {};
  authorization = new AuthorizationJWT(samplePermissions, {getDecodedPayload});
  authorization.decode()(req,res,middleware);
});

test('Call isAuth when no decoded payload available', () => {
  req={};
  authorization = new AuthorizationJWT(samplePermissions);
  authorization.decode()(req,res,err=>{
    expect(authorization.isAuth(req,'admin')).toBe(false);
  })
});

test('Call isAuth (expect success)', () => {
  req={};
  const getDecodedPayload = req => ({ id: '10', role: 'user' });
  authorization = new AuthorizationJWT(samplePermissions,{getDecodedPayload});
  authorization.decode()(req,res,err=>{
    expect(authorization.isAuth(req,'user')).toBe(true);
  });
});
