#!/usr/bin/env node
// Verify all Mermaid diagrams in ARCHITECTURE.md parse correctly.
// Uses mermaid@10 (the version GitHub renders with).
//
// Usage: node scripts/check-mermaid.mjs
// Or:    make check-mermaid (if added to Makefile)
import mermaid from 'mermaid';
import fs from 'fs';

const md = fs.readFileSync('docs/ARCHITECTURE.md', 'utf8');
const blocks = [];
const re = /```mermaid\n([\s\S]*?)\n```/g;
let m;
while ((m = re.exec(md)) !== null) blocks.push(m[1]);

console.log(`Found ${blocks.length} mermaid blocks in ARCHITECTURE.md`);
let failed = 0;
for (let i = 0; i < blocks.length; i++) {
    try {
        await mermaid.parse(blocks[i]);
        console.log(`  block ${i + 1}: OK`);
    } catch (err) {
        failed++;
        console.log(`  block ${i + 1}: FAILED`);
        console.log(`    ${err.message.split('\n')[0]}`);
        const lines = blocks[i].split('\n');
        for (let j = 0; j < Math.min(3, lines.length); j++) {
            console.log(`    line ${j + 1}: ${lines[j]}`);
        }
    }
}
process.exit(failed > 0 ? 1 : 0);