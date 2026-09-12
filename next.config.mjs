/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config) => {
    config.resolve.alias = {
      ...config.resolve.alias,
      "@x402": false,
      "@solana": false,
      "@react-native-async-storage/async-storage": false,
      "react-native": false,
      "react-native-webview": false,
    };
    return config;
  },
};

export default nextConfig;
