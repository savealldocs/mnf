import * as utils from '../../src/utils/main';
import * as validate from '../../src/utils/validator';
import * as authConfirmSignUp from '../../src/auth/authConfirmSignUp';

describe('authStartSession', () => {
  afterEach(() => {
    jest.resetAllMocks();
    jest.restoreAllMocks();
    jest.resetModules();
  });

  const payload = {
    body:
      '{ "code":"12345432","email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds","mobileNumber":"0481323122"}',
  };
  test('authCreateValidateUser should return valid response ', async () => {
    validate.validateParams = jest.fn();
    validate.validateParams.mockReturnValue(true);

    utils.isEmail = jest.fn();
    utils.isEmail.mockReturnValue(true);

    utils.isTokenExpired = jest.fn();
    utils.isTokenExpired.mockReturnValue(false);

    utils.validateToken = jest.fn();
    utils.validateToken.mockReturnValue(true);

    validate.isValidUserMobileNumber = jest.fn();
    validate.isValidUserMobileNumber.mockReturnValue(true);

    utils.encrypt = jest.fn();
    utils.encrypt.mockReturnValue('7657657');
    utils.validateCode = jest.fn();
    utils.validateCode.mockResolvedValue(true);

    utils.deleteUserAccount = jest.fn();
    utils.deleteUserAccount.mockResolvedValue(true);
    const res = true;
    const result = await authConfirmSignUp.main(payload);
    expect(JSON.parse(result.body).status).toEqual(res);
  });
});
