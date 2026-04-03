import { spawn, exec, execSync } from 'child_process'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import { promisify } from 'util'

const execAsync = promisify(exec)

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  
  try {
    // Try to find the port-kill-console binary
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Clear process history using our Rust application
    await clearProcessHistory(binaryPath)
    
    return {
      success: true,
      message: 'Process history cleared successfully',
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error clearing process history:', error)
    
    return {
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    }
  }
})

function findPortKillBinary(defaultPath: string): string | null {
  // Check if the default path exists
  if (existsSync(defaultPath)) {
    return defaultPath
  }
  
  // Try common locations for port-kill-console
  const possiblePaths = [
    './target/release/port-kill-console',
    './target/release/port-kill-console.exe',
    './target/debug/port-kill-console',
    './target/debug/port-kill-console.exe',
    '../target/release/port-kill-console',
    '../target/release/port-kill-console.exe',
    '../target/debug/port-kill-console',
    '../target/debug/port-kill-console.exe',
    '/usr/local/bin/port-kill-console',
    '/opt/homebrew/bin/port-kill-console',
    join(process.env.HOME || '', '.local', 'bin', 'port-kill-console'),
    'C:\\Program Files\\port-kill\\port-kill-console.exe',
    join(process.env.USERPROFILE || '', 'AppData', 'Local', 'port-kill', 'port-kill-console.exe')
  ]
  
  for (const path of possiblePaths) {
    if (existsSync(path)) {
      return path
    }
  }
  
  return null
}

async function clearProcessHistory(binaryPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // Build command arguments for clearing history
    const args = [
      '--clear-history'
    ]
    
    const rustApp = spawn(binaryPath, args, {
      stdio: ['pipe', 'pipe', 'pipe']
    })
    
    let stdout = ''
    let stderr = ''
    
    rustApp.stdout.on('data', (data) => {
      stdout += data.toString()
    })
    
    rustApp.stderr.on('data', (data) => {
      stderr += data.toString()
    })
    
    rustApp.on('close', (code) => {
      if (code !== 0) {
        console.warn(`Rust app failed with code ${code}: ${stderr}`)
        reject(new Error(`Failed to clear history: ${stderr}`))
        return
      }
      
      resolve()
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      reject(error)
    })
  })
}
