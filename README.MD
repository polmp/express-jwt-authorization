# Express JWT Authorization

[![Code Style](https://badgen.net/badge/code%20style/airbnb/ff5a5f?icon=airbnb)](https://github.com/airbnb/javascript)

Simple middleware that allows protecting routes for a specific role or permission based on [express-jwt-permissions](https://github.com/MichielDeMey/express-jwt-permissions) approach.

With this module, there is no need of saving the scopes directly in the JWT. Simply set a role for a user and control all its permissions of that role in the backend.

## Install

```
npm install express-jwt-authorization --save
```

## Usage

This middleware has to be used in conjunction with another JWT authentication middleware that verifies and decodes the token. We reccommend [express-jwt](https://github.com/auth0/express-jwt) or building your own.

## Configuration

Set a custom JSON with all the permissions and their roles. For example:

```json
{
  "admin": [
    "recoverPassword",
    "generateToken",
    "changePassword",
    "changeEmail",
    "deleteUser",
    "getUserData"
  ],
  "user": ["recoverPassword", "changePassword", "changeEmail"]
}
```

Then, call the constructor in the following way:

```javascript
var jwtAuth = require('express-jwt-authorization');
jwtAuth = new jwtAuth({
  admin: [
    'recoverPassword',
    'generateToken',
    'changePassword',
    'changeEmail',
    'deleteUser',
    'getUserData',
  ],
  user: ['recoverPassword', 'changePassword', 'changeEmail'],
});
```

If you have stored the information of the token in a different property you can set the `userParameter` option.

If the role field is different from the default, just set the `roleParameter` option.

As an example, if the user data can be accessed within `req.custom_user` and the role property is called `custom_role`, you need to pass the following configuration as the second argument:

```javascript
new jwtAuth(
  {
    admin: ['recoverPassword', 'generateToken'],
    user: ['recoverPassword', 'changePassword'],
  },
  { userParameter: 'custom_user', roleParameter: 'custom_role' },
);
```

## Main usage

### Check if a role is allowed to access a particular resource

```javascript
// Only users with the role admin are allowed
app.use(jwtAuth.checkRole('admin'));
```

### Check if a user has particular permissions based on role

Of course, a permission can be set for different roles. If you need to distinguish between roles for a particular use, just check the `req.user.role` variable.

- Simple string

```javascript
// Only roles with the permission 'generateToken' are allowed
app.use(jwtAuth.checkPermission('generateToken'));
```

This library allows to do logical combination of permissions using nested arrays.

- Array of strings

```javascript
// 'modify' AND 'delete' permissions are needed
router.get(
  '/resource',
  jwtAuth.checkPermission(['modify', 'delete']),
  (req, res) => {
    return res.status(200).json({ status: 'OK' });
  },
);
```

- Array of arrays of strings

```javascript
// 'modify' OR 'delete' permissions are needed
app.use(jwtAuth.checkPermission([['modify'], ['delete']]));

// 'delete' OR ('modify' AND 'read') permissions are needed
app.use(jwtAuth.checkPermission([['delete'], ['modify', 'read']]));
```

## Error handling

When the error is due to a bad configuration of the module, a standard Error object is thrown.
In the other cases, an 'UnauthorizedError' object is thrown.

You can add your custom logic in a middleware with four arguments as Express recommends in the following way:

```javascript
app.use(function(err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    if (err.code === 'permission_not_allowed') {
      return res.status(403).send('not allowed');
    }
  }
});
```

Check `err.code` for additional information of the error.

## Related Modules

- [express-jwt](https://github.com/auth0/express-jwt) - Validates JWT and sets req.user
- [express-jwt-permissions](https://github.com/MichielDeMey/express-jwt-permissions) - Permissions middleware for JWT tokens

## Tests

    $ npm install
    $ npm test

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
