export type CliParams = {
  host?: string;
  user?: string;
  pass?: string;
  id?: string;
  secret?: string;
  cert?: string;
  key?: string;
  ca?: string;
  passphrase?: string;
  certWatchIntervalMin?: number;
  mcpPort?: number;
  allowOrigin?: string[];
  bind?: string;
  shutdownDrainSeconds?: number;
  stdio?: boolean;
};
