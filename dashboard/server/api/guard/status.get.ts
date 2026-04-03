import { spawn, exec } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'

export default defineEventHandler(async (event) => {
  try {
    const binaryPath = findPortKillBinary()
    
    if (!binaryPath) {
      throw new Error('Port Kill binary not found. Please build the Rust application first.')
    }
    
    const status = await getGuardStatus(binaryPath)
    
    return {
      success: true,
      status,
      timestamp: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error fetching guard status:', error)
    
    return {
      success: false,
      error: error.message,
      status: null,
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

async function getGuardStatus(binaryPath: string): Promise<any | null> {
  return new Promise((resolve, reject) => {
    // Use a simpler approach with timeout to avoid hanging
    
    exec('ps aux | grep "port-kill-console.*guard-mode" | grep -v grep', { timeout: 5000 }, (error: any, stdout: string, stderr: string) => {
      if (error && error.code !== 1) { // code 1 means no matches found, which is OK
        console.error('Error checking guard status:', error)
        reject(error)
        return
      }
      
      const isGuardRunning = stdout.trim().length > 0
      
      if (isGuardRunning) {
        // Extract guard ports from the command line
        const portMatch = stdout.match(/--guard-ports\s+([0-9,]+)/)
        const watchedPorts = portMatch ? portMatch[1].split(',').map(Number) : [3000, 3001, 3002, 8000, 8080, 9000]
        
        // Check for auto-resolve flag
        const autoResolve = stdout.includes('--auto-resolve')
        
        // Read actual reservations from file
        let activeReservations = []
        try {
          const reservationsPath = join(homedir(), '.port-kill', 'reservations.json')
          if (existsSync(reservationsPath)) {
            const reservationsData = readFileSync(reservationsPath, 'utf8')
            const reservations = JSON.parse(reservationsData)
            activeReservations = Object.values(reservations)
          }
        } catch (error) {
          console.error('Error reading reservations:', error)
        }
        
        const status = {
          is_active: true,
          watched_ports: watchedPorts,
          active_reservations: activeReservations,
          conflicts_resolved: 0,
          last_activity: new Date().toISOString(),
          auto_resolve_enabled: autoResolve
        }
        
        resolve(status)
      } else {
        // Guard is not running
        const status = {
          is_active: false,
          watched_ports: [3000, 3001, 3002, 8000, 8080, 9000],
          active_reservations: [],
          conflicts_resolved: 0,
          last_activity: null,
          auto_resolve_enabled: false
        }
        
        resolve(status)
      }
    })
  })
}
