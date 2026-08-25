/* מעתיק את קובץ האפליקציה היחיד אל תיקיית הנכסים הסטטיים של ה-Worker. */
import { mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src  = resolve(here, '..', 'index.html');
const dest = resolve(here, 'public', 'index.html');

if (!existsSync(src)) {
  console.error('לא נמצא ' + src);
  process.exit(1);
}
mkdirSync(dirname(dest), { recursive: true });
copyFileSync(src, dest);
console.log('build: index.html -> worker/public/index.html');
