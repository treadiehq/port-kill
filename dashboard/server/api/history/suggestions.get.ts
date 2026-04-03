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
    
    // Get suggestions from Rust app
    const suggestions = await getIgnoreSuggestions(binaryPath)
    
    return {
      success: true,
      suggestions,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching ignore suggestions:', error)
    
    return {
      success: false,
      error: error.message,
      suggestions: null,
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

async function getIgnoreSuggestions(binaryPath: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const rustApp = spawn(binaryPath, ['--show-suggestions', '--json'], {
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
        resolve(null)
        return
      }
      
      try {
        // Parse JSON output from Rust app
        const lines = stdout.trim().split('\n')
        let suggestions = null
        
        for (const line of lines) {
          if (line.trim()) {
            try {
              const parsed = JSON.parse(line)
              if (parsed.suggested_ports !== undefined) {
                suggestions = parsed
                break
              }
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        }
        
        resolve(suggestions)
      } catch (error) {
        reject(error)
      }
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve(null)
    })
  })
}
