import { spawn } from 'child_process'
import { existsSync } from 'fs'
import { join } from 'path'

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig()
  
  try {
    // Try to find the port-kill-console binary
    const binaryPath = findPortKillBinary(config.portKillBinaryPath)
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    // Get frequent offenders from Rust app
    const offenders = await getFrequentOffenders(binaryPath)
    
    return {
      success: true,
      offenders,
      count: offenders.length,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching frequent offenders:', error)
    
    return {
      success: false,
      error: error.message,
      offenders: [],
      count: 0,
      timestamp: new Date().toISOString()
    }
  }
})

function findPortKillBinary(defaultPath: string): string | null {
  // Check if the default path exists
  if (existsSync(defaultPath)) {
    return defaultPath
  }
  
  // Try common locations
  const commonPaths = [
    join(process.cwd(), 'target', 'release', 'port-kill-console'),
    join(process.cwd(), 'target', 'release', 'port-kill-console.exe'),
    join(process.cwd(), '..', 'target', 'release', 'port-kill-console'),
    join(process.cwd(), '..', 'target', 'release', 'port-kill-console.exe'),
    './target/release/port-kill-console',
    './target/release/port-kill-console.exe',
    '../target/release/port-kill-console',
    '../target/release/port-kill-console.exe',
    '/usr/local/bin/port-kill-console',
    '/opt/homebrew/bin/port-kill-console',
    join(process.env.HOME || '', '.local', 'bin', 'port-kill-console'),
  ]
  
  for (const path of commonPaths) {
    if (existsSync(path)) {
      return path
    }
  }
  
  return null
}

async function getFrequentOffenders(binaryPath: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const rustApp = spawn(binaryPath, ['--show-offenders', '--json'], {
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
        resolve([])
        return
      }
      
      try {
        // Parse JSON output from Rust app
        const lines = stdout.trim().split('\n')
        const offenders = []
        
        for (const line of lines) {
          if (line.trim()) {
            try {
              const offender = JSON.parse(line)
              if (offender.process_name && offender.port) {
                offenders.push(offender)
              }
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        }
        
        resolve(offenders)
      } catch (error) {
        reject(error)
      }
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve([])
    })
  })
}
