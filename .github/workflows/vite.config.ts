import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';
import obfuscator from 'rollup-plugin-javascript-obfuscator';

export default defineConfig(({ command }) => {
  const isBuild = command === 'build';
  return {
    base: './',
    plugins: [
      react(),
      tailwindcss(),
      ...(isBuild ? [
        obfuscator({
          compact: true,
          identifierNamesGenerator: 'hexadecimal',
          selfDefending: true,
          controlFlowFlattening: false,
          deadCodeInjection: false,
          stringArray: true,
          stringArrayEncoding: ['base64'],
          stringArrayThreshold: 0.85,
          stringArrayRotate: true,
          stringArrayShuffle: true,
          stringArrayIndexShift: true,
          stringArrayCallsTransform: true,
          stringArrayCallsTransformThreshold: 0.75,
          splitStrings: true,
          splitStringsChunkLength: 8,
          transformObjectKeys: true,
          numbersToExpressions: true,
          unicodeEscapeSequence: false,
          exclude: ['node_modules/**', '**/*.d.ts'],
          globalIgnoreKeys: [
            'AirConsole',
            'airconsole',
            'airconsoleInstance',
            'google',
            'adsbygoogle',
            'gapi',
            'monetag',
            'kongregate',
            'kongregateAPI',
            'show_9845019',
            'GXC',
            'gxc',
            'y8',
            'isGXReady',
            'gdsdk',
            'GameDistribution',
            '__STUDIO_SIGNATURE',
            '__EACHONE_INFORMATION_CHANNEL_STUDIO_SIGNATURE',
          ],
        }),
      ] : []),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    build: {
      target: ['es2015', 'chrome60', 'safari11'],
      cssTarget: 'chrome60',
      chunkSizeWarningLimit: 2000,
      minify: 'terser' as const,
      terserOptions: {
        compress: {
          drop_console: false,
          drop_debugger: true,
          pure_funcs: ['console.debug'],
          passes: 2,
        },
        mangle: {
          toplevel: true,
          keep_classnames: false,
          keep_fnames: false,
        },
        format: {
          comments: false,
        },
      },
      sourcemap: false,
      rollupOptions: {
        input: {
          main: path.resolve(__dirname, 'index.html'),
        },
        output: {
          entryFileNames: 'assets/[name].js',
          chunkFileNames: 'assets/[name].js',
          assetFileNames: 'assets/[name].[ext]',
          manualChunks: {
            'vendor-react': ['react', 'react-dom'],
            'vendor-icons': ['lucide-react']
          }
        }
      }
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
    },
  };
});
