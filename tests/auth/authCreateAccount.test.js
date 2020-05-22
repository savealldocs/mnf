import * as utils from '../../src/utils/main';
import * as validate from '../../src/utils/validator';
import { main } from '../../src/auth/authCreateAccount';

describe('authStartSession', () => {
  afterEach(() => {
    jest.resetAllMocks();
    jest.restoreAllMocks();
    jest.resetModules();
  });

  test('Create Cognito user Account', async () => {
    const payload = {
      body:
        '{ "code":"12345432","email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds","mobileNumber":"0481323122"}',
    };
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

    utils.createAccount = jest.fn();
    utils.createAccount.mockResolvedValue(true);
    const res = true;
    const result = await main(payload);
    expect(JSON.parse(result.body).status).toEqual(res);
  });
});
