import _ from 'lodash';

/**
 * response
 *
 * add CORS header and stringify object to string in response
 *
 * @param http statusCode
 * @param result axios response object or string
 *
 * @returns object for lambda handler
 */
exports.response = (statusCode, result) => {
  const headers = {};
  let body;

  if (typeof result === 'string') {
    body = result;
  } else {
    // headers = _.get(result, 'headers', {});
    body = JSON.stringify(_.get(result, 'data', result));
  }

  headers['Access-Control-Allow-Origin'] = '*';

  return {
    statusCode,
    headers,
    body,
  };
};
