import _ from 'lodash';
import { main } from '../../src/auth/authStartSession';

import * as validate from '../../src/utils/validator';

describe('authStartSession', () => {
  afterEach(() => {
    jest.resetAllMocks();
    jest.restoreAllMocks();
    jest.resetModules();
  });
  test('Should return error response when payload params are undefined or carries no value', async () => {
    const res = {
      body: '{"status":false,"error":{"description":"INVALID_PARAMS"}}',
      headers: { 'Access-Control-Allow-Origin': '*' },
      statusCode: 401,
    };

    validate.validateParams = jest.fn();
    validate.validateParams.mockReturnValue(false);

    const result = await main({
      body: '{ "email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds"}',
    });
    expect(result).toEqual(res);
  });

  test('Should return token and status true', async () => {
    const res = true;
    validate.validateParams = jest.fn();
    validate.validateParams.mockReturnValue(true);
    const result = await main({
      body: '{ "email": "catchup66@aol.com", "deviceId": "81323177", "userAgent": "sadsds"}',
    });
    let resultCloned = _.clone(JSON.parse(JSON.stringify(result)));
    resultCloned = JSON.parse(resultCloned.body).status;

    expect(resultCloned).toEqual(res);
  });
});
