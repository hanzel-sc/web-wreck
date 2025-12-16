/**
 * Simple logging utilities
 */

export const log = {
  phase(name: string): void {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  ${name}`);
    console.log('='.repeat(60));
  },
  
  info(message: string): void {
    console.log(`[INFO] ${message}`);
  },
  
  warn(message: string): void {
    console.warn(`[WARN] ${message}`);
  },
  
  error(message: string, error?: any): void {
    console.error(`[ERROR] ${message}`);
    if (error) {
      console.error(error);
    }
  },
  
  success(message: string): void {
    console.log(`[✓] ${message}`);
  },
};