#!/usr/bin/env node

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Configuration
const config = {
  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/museum_collection',
  backupDir: process.env.BACKUP_STORAGE_PATH || './backups',
  retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS) || 30,
  compressionLevel: 6, // gzip compression level (1-9)
};

// Extract database name from MongoDB URI
function getDatabaseName(uri) {
  const match = uri.match(/\/([^/?]+)(\?|$)/);
  return match ? match[1] : 'museum_collection';
}

// Create backup directory if it doesn't exist
function ensureBackupDirectory() {
  if (!fs.existsSync(config.backupDir)) {
    fs.mkdirSync(config.backupDir, { recursive: true });
    console.log(`Created backup directory: ${config.backupDir}`);
  }
}

// Generate backup filename with timestamp
function generateBackupFilename() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dbName = getDatabaseName(config.mongoUri);
  return `${dbName}-backup-${timestamp}.gz`;
}

// Perform database backup using mongodump
async function performBackup() {
  try {
    const dbName = getDatabaseName(config.mongoUri);
    const backupFilename = generateBackupFilename();
    const backupPath = path.join(config.backupDir, backupFilename);
    
    console.log(`Starting backup of database: ${dbName}`);
    console.log(`Backup will be saved to: ${backupPath}`);
    
    // Extract connection details from URI
    const uriParts = config.mongoUri.match(/mongodb:\/\/(?:([^:]+):([^@]+)@)?([^:\/]+)(?::(\d+))?\/(.+)/);
    
    let mongodumpCmd = 'mongodump';
    
    if (uriParts) {
      const [, username, password, host, port, database] = uriParts;
      
      mongodumpCmd += ` --host ${host}${port ? `:${port}` : ''}`;
      mongodumpCmd += ` --db ${database}`;
      
      if (username && password) {
        mongodumpCmd += ` --username ${username} --password ${password}`;
      }
    } else {
      mongodumpCmd += ` --uri "${config.mongoUri}"`;
    }
    
    // Add compression and output options
    mongodumpCmd += ` --archive | gzip -${config.compressionLevel} > "${backupPath}"`;
    
    const startTime = Date.now();
    await execAsync(mongodumpCmd);
    const duration = Date.now() - startTime;
    
    // Get backup file size
    const stats = fs.statSync(backupPath);
    const fileSizeMB = (stats.size / (1024 * 1024)).toFixed(2);
    
    console.log(`✅ Backup completed successfully!`);
    console.log(`   File: ${backupFilename}`);
    console.log(`   Size: ${fileSizeMB} MB`);
    console.log(`   Duration: ${duration}ms`);
    
    return {
      success: true,
      filename: backupFilename,
      path: backupPath,
      size: stats.size,
      duration,
    };
    
  } catch (error) {
    console.error(`❌ Backup failed:`, error.message);
    return {
      success: false,
      error: error.message,
    };
  }
}

// Clean up old backup files based on retention policy
async function cleanupOldBackups() {
  try {
    const files = fs.readdirSync(config.backupDir);
    const backupFiles = files.filter(file => file.endsWith('.gz') && file.includes('backup'));
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - config.retentionDays);
    
    let deletedCount = 0;
    let deletedSize = 0;
    
    for (const file of backupFiles) {
      const filePath = path.join(config.backupDir, file);
      const stats = fs.statSync(filePath);
      
      if (stats.mtime < cutoffDate) {
        deletedSize += stats.size;
        fs.unlinkSync(filePath);
        deletedCount++;
        console.log(`🗑️  Deleted old backup: ${file}`);
      }
    }
    
    if (deletedCount > 0) {
      const deletedSizeMB = (deletedSize / (1024 * 1024)).toFixed(2);
      console.log(`✅ Cleanup completed: ${deletedCount} files deleted (${deletedSizeMB} MB freed)`);
    } else {
      console.log(`✅ No old backups to clean up`);
    }
    
    return { deletedCount, deletedSize };
    
  } catch (error) {
    console.error(`❌ Cleanup failed:`, error.message);
    return { error: error.message };
  }
}

// List existing backups
function listBackups() {
  try {
    const files = fs.readdirSync(config.backupDir);
    const backupFiles = files
      .filter(file => file.endsWith('.gz') && file.includes('backup'))
      .map(file => {
        const filePath = path.join(config.backupDir, file);
        const stats = fs.statSync(filePath);
        return {
          filename: file,
          size: stats.size,
          created: stats.mtime,
          sizeMB: (stats.size / (1024 * 1024)).toFixed(2),
        };
      })
      .sort((a, b) => b.created - a.created);
    
    console.log(`\n📋 Available backups (${backupFiles.length} files):`);
    
    if (backupFiles.length === 0) {
      console.log('   No backups found');
      return;
    }
    
    backupFiles.forEach((backup, index) => {
      const age = Math.floor((Date.now() - backup.created.getTime()) / (1000 * 60 * 60 * 24));
      console.log(`   ${index + 1}. ${backup.filename}`);
      console.log(`      Size: ${backup.sizeMB} MB, Age: ${age} days`);
    });
    
    const totalSize = backupFiles.reduce((sum, backup) => sum + backup.size, 0);
    const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(2);
    console.log(`\n   Total backup size: ${totalSizeMB} MB`);
    
  } catch (error) {
    console.error(`❌ Failed to list backups:`, error.message);
  }
}

// Restore database from backup
async function restoreBackup(backupFilename) {
  try {
    const backupPath = path.join(config.backupDir, backupFilename);
    
    if (!fs.existsSync(backupPath)) {
      throw new Error(`Backup file not found: ${backupFilename}`);
    }
    
    console.log(`Starting restore from backup: ${backupFilename}`);
    
    const dbName = getDatabaseName(config.mongoUri);
    
    // Extract connection details from URI
    const uriParts = config.mongoUri.match(/mongodb:\/\/(?:([^:]+):([^@]+)@)?([^:\/]+)(?::(\d+))?\/(.+)/);
    
    let mongorestoreCmd = `gunzip -c "${backupPath}" | mongorestore`;
    
    if (uriParts) {
      const [, username, password, host, port, database] = uriParts;
      
      mongorestoreCmd += ` --host ${host}${port ? `:${port}` : ''}`;
      mongorestoreCmd += ` --db ${database}`;
      
      if (username && password) {
        mongorestoreCmd += ` --username ${username} --password ${password}`;
      }
    } else {
      mongorestoreCmd += ` --uri "${config.mongoUri}"`;
    }
    
    mongorestoreCmd += ' --archive --drop'; // Drop existing collections before restore
    
    const startTime = Date.now();
    await execAsync(mongorestoreCmd);
    const duration = Date.now() - startTime;
    
    console.log(`✅ Restore completed successfully!`);
    console.log(`   Duration: ${duration}ms`);
    
    return {
      success: true,
      duration,
    };
    
  } catch (error) {
    console.error(`❌ Restore failed:`, error.message);
    return {
      success: false,
      error: error.message,
    };
  }
}

// Main function
async function main() {
  const command = process.argv[2];
  
  console.log('🏛️  Museum Collection Database Backup Tool');
  console.log('==========================================\n');
  
  ensureBackupDirectory();
  
  switch (command) {
    case 'backup':
      await performBackup();
      await cleanupOldBackups();
      break;
      
    case 'list':
      listBackups();
      break;
      
    case 'cleanup':
      await cleanupOldBackups();
      break;
      
    case 'restore':
      const backupFilename = process.argv[3];
      if (!backupFilename) {
        console.error('❌ Please specify a backup filename to restore');
        console.log('Usage: node backup-database.js restore <backup-filename>');
        process.exit(1);
      }
      await restoreBackup(backupFilename);
      break;
      
    default:
      console.log('Usage:');
      console.log('  node backup-database.js backup   - Create a new backup');
      console.log('  node backup-database.js list     - List available backups');
      console.log('  node backup-database.js cleanup  - Clean up old backups');
      console.log('  node backup-database.js restore <filename> - Restore from backup');
      console.log('\nConfiguration:');
      console.log(`  Database: ${getDatabaseName(config.mongoUri)}`);
      console.log(`  Backup directory: ${config.backupDir}`);
      console.log(`  Retention: ${config.retentionDays} days`);
      break;
  }
}

// Handle errors gracefully
process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error.message);
  process.exit(1);
});

// Run the script
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  performBackup,
  cleanupOldBackups,
  listBackups,
  restoreBackup,
  config,
};

