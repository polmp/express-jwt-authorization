class UnauthorizedError extends Error {
  constructor(code, message) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.message = message;
    Error.captureStackTrace(this, this.constructor);
  }
}
module.exports = UnauthorizedError;
