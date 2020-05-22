import _ from 'lodash';
import * as validate from '../../src/utils/validator';
import * as utils from '../../src/utils/main';
import * as createValidateUser from '../../src/auth/authCreateValidateUser';

describe('authCreateValidateUser', () => {
  afterEach(() => {
    jest.resetAllMocks();
    jest.restoreAllMocks();
    jest.resetModules();
  });

  test('Is Token Expired', async () => {
    validate.validateToken = jest.fn();
    validate.validateToken.mockReturnValue(false);
    const token = await utils.encrypt({
      body: '{ "email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds"}',
    });
    const tokenExpired = await utils.isTokenExpired(token);
    expect(tokenExpired).toBe(false);
  });

  test('Is ValidToken or not', async () => {
    const payload = {
      body:
        '{ "email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds","mobileNumber":"0481323122"}',
    };
    const cloneBody = JSON.parse(_.clone(payload.body));
    delete cloneBody.mobileNumber;
    const token = await utils.encrypt(cloneBody);
    const isvalidToken = await utils.validateToken(token, cloneBody);
    expect(isvalidToken).toBe(true);
  });

  test('Is ValidTPhone number', async () => {
    const phoneNumberAu = '+61 481323188';
    const phoneNumberSg = '+65 85554970';

    const isAuPhoneValid = validate.isValidUserMobileNumber(phoneNumberAu, 'AU');
    expect(isAuPhoneValid).toBe('+61481323188');
    const isSgPhoneValid = validate.isValidUserMobileNumber(phoneNumberSg, 'SG');
    expect(isSgPhoneValid).toBe('+6585554970');
  });

  test('authCreateValidateUser should return valid response ', async () => {
    const payload = {
      body: '{"mobileNumber":"0481323122","email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds"}',
    };
    const cloneBody = JSON.parse(_.clone(payload.body));
    delete cloneBody.mobileNumber;
    const token = await utils.encrypt(cloneBody);

    validate.validateParams = jest.fn();
    validate.validateParams.mockReturnValue(true);

    utils.isEmail = jest.fn();
    utils.isEmail.mockReturnValue(true);

    utils.isTokenExpired = jest.fn();
    utils.isTokenExpired.mockReturnValue(false);

    utils.validateToken = jest.fn();
    utils.validateToken.mockReturnValue(true);

    createValidateUser.getUserAttribute = jest.fn();
    createValidateUser.getUserAttribute.mockReturnValue(true);

    utils.deleteConfirmedUser = jest.fn();
    utils.deleteConfirmedUser.mockResolvedValue(true);

    utils.signUpGenerateCode = jest.fn();
    utils.signUpGenerateCode.mockReturnValue(true);

    utils.encrypt = jest.fn();
    utils.encrypt.mockResolvedValue(token);

    const res = {
      // eslint-disable-next-line no-useless-concat
      body: '{"status":true,"token":"' + `${token}` + '","mobileNumber":"0481323122"}',
      headers: { 'Access-Control-Allow-Origin': '*' },
      statusCode: 200,
    };
    const result = await createValidateUser.main(payload);

    expect(result).toEqual(res);
  });
});
