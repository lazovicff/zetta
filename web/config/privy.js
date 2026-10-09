export const privyConfig = {
  loginMethods: ["wallet"], // WalletConnect / external wallets only
  appearance: { theme: "dark" },
  embeddedWallets: {
    createOnLogin: "off", // never create an embedded wallet
  },
};
