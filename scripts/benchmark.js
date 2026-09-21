import { performance } from 'node:perf_hooks';
import { MemoryStorage, VaultManager } from '../vault-secure.js';

const rounds = Math.max(1, Number(process.env.BENCHMARK_ROUNDS || 3));
const samples = [];
for (let index = 0; index < rounds; index++) {
  const started = performance.now();
  const vault = new VaultManager(new MemoryStorage());
  await vault.create('benchmark-user', 'synthetic-benchmark-password');
  await vault.addSecret({ name: 'BENCHMARK_KEY', domain: 'example.com', value: 'synthetic-benchmark-value' });
  await vault.resolve('BENCHMARK_KEY', 'https://example.com');
  samples.push(performance.now() - started);
}
const sorted = [...samples].sort((a, b) => a - b);
const median = sorted[Math.floor(sorted.length / 2)];
console.log(JSON.stringify({ version: '2.0.0', rounds, operation: 'create-add-resolve', milliseconds: { min: Math.min(...samples), median, max: Math.max(...samples) }, syntheticData: true }, null, 2));
