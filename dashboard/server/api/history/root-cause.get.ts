import { spawn } from 'child_process'
import { existsSync } from 'fs'
import { join } from 'path'

export default defineEventHandler(async (event) => {
  try {
    const binaryPath = findPortKillBinary()
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    const analysis = await getRootCauseAnalysis(binaryPath)
    
    return {
      success: true,
      analysis,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching root cause analysis:', error)
    
    return {
      success: false,
      error: error.message,
      analysis: null,
      timestamp: new Date().toISOString()
    }
  }
})

function findPortKillBinary(): string | null {
  // Try common locations
  const commonPaths = [
    join(process.cwd(), 'target', 'release', 'port-kill-console'),
    join(process.cwd(), 'target', 'release', 'port-kill-console.exe'),
    join(process.cwd(), '..', 'target', 'release', 'port-kill-console'),
    join(process.cwd(), '..', 'target', 'release', 'port-kill-console.exe'),
    '/usr/local/bin/port-kill-console',
    '/opt/port-kill/port-kill-console',
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

async function getRootCauseAnalysis(binaryPath: string): Promise<any | null> {
  return new Promise((resolve, reject) => {
    const args = ['--show-root-cause', '--json']
    
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
        resolve(null)
        return
      }
      
      try {
        // Filter out debug output and extract JSON
        const lines = stdout.split('\n')
        let jsonLine = ''
        
        for (const line of lines) {
          const trimmed = line.trim()
          // Look for lines that start with { (JSON)
          if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
            jsonLine = trimmed
            break
          }
        }
        
        if (!jsonLine) {
          throw new Error('No valid JSON found in output')
        }
        
        const analysis = JSON.parse(jsonLine)
        resolve(analysis)
      } catch (error) {
        console.error('JSON parsing error:', error)
        console.error('Raw output:', stdout)
        reject(error)
      }
    })
    
    rustApp.on('error', (error) => {
      console.warn(`Failed to spawn Rust app: ${error.message}`)
      resolve(null)
    })
  })
}
