import { olog } from '@optussport/ml-utility';

let logger;
export const Logger = ({ userAgent, fnTag }) => {
  logger = olog(fnTag, { userAgent });
  return logger;
};

export const getLogger = () => {
  if (!logger) {
    Logger({ fnTag: 'default' });
  }

  return logger;
};
