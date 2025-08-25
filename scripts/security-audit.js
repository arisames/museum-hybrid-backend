#!/usr/bin/env node

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Security audit configuration
const config = {
  auditLevel: process.env.AUDIT_LEVEL || 'moderate', // low, moderate, high, critical
  autoFix: process.env.AUTO_FIX === 'true',
  reportFormat: process.env.REPORT_FORMAT || 'json', // json, text, html
  outputDir: process.env.AUDIT_OUTPUT_DIR || './security-reports',
  excludeDevDependencies: process.env.NODE_ENV === 'production',
};

class SecurityAuditor {
  constructor(config) {
    this.config = config;
    this.results = {
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      outdatedPackages: [],
      securityHeaders: [],
      environmentChecks: [],
      recommendations: [],
      summary: {
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
        info: 0,
      }
    };
    
    this.ensureOutputDirectory();
  }
  
  ensureOutputDirectory() {
    if (!fs.existsSync(this.config.outputDir)) {
      fs.mkdirSync(this.config.outputDir, { recursive: true });
    }
  }
  
  async runNpmAudit() {
    console.log('🔍 Running npm security audit...');
    
    try {
      const auditLevel = this.config.auditLevel;
      const command = `npm audit --audit-level=${auditLevel} --json`;
      
      const { stdout, stderr } = await execAsync(command);
      const auditResult = JSON.parse(stdout);
      
      if (auditResult.vulnerabilities) {
        Object.entries(auditResult.vulnerabilities).forEach(([pkg, vuln]) => {
          this.results.vulnerabilities.push({
            package: pkg,
            severity: vuln.severity,
            title: vuln.title,
            url: vuln.url,
            range: vuln.range,
            fixAvailable: vuln.fixAvailable,
          });
          
          this.results.summary[vuln.severity]++;
        });
      }
      
      console.log(`✅ Found ${this.results.vulnerabilities.length} vulnerabilities`);
      
      // Auto-fix if enabled and safe
      if (this.config.autoFix && this.results.vulnerabilities.length > 0) {
        await this.autoFixVulnerabilities();
      }
      
    } catch (error) {
      console.error('❌ npm audit failed:', error.message);
      this.results.vulnerabilities.push({
        package: 'audit-error',
        severity: 'high',
        title: 'Failed to run npm audit',
        description: error.message,
      });
    }
  }
  
  async autoFixVulnerabilities() {
    console.log('🔧 Attempting to auto-fix vulnerabilities...');
    
    try {
      // Try npm audit fix first (safer)
      await execAsync('npm audit fix');
      console.log('✅ Applied automatic fixes');
      
      // Check if force fix is needed for remaining issues
      const { stdout } = await execAsync('npm audit --json');
      const remainingIssues = JSON.parse(stdout);
      
      if (remainingIssues.metadata?.vulnerabilities?.total > 0) {
        console.log('⚠️  Some vulnerabilities require manual intervention');
        this.results.recommendations.push({
          type: 'manual-fix',
          message: 'Run "npm audit fix --force" to fix remaining issues (may introduce breaking changes)',
          severity: 'moderate',
        });
      }
      
    } catch (error) {
      console.error('❌ Auto-fix failed:', error.message);
      this.results.recommendations.push({
        type: 'fix-error',
        message: 'Automatic fixes failed, manual intervention required',
        severity: 'high',
        details: error.message,
      });
    }
  }
  
  async checkOutdatedPackages() {
    console.log('📦 Checking for outdated packages...');
    
    try {
      const { stdout } = await execAsync('npm outdated --json');
      const outdated = JSON.parse(stdout || '{}');
      
      Object.entries(outdated).forEach(([pkg, info]) => {
        const severity = this.getOutdatedSeverity(info.current, info.latest);
        
        this.results.outdatedPackages.push({
          package: pkg,
          current: info.current,
          wanted: info.wanted,
          latest: info.latest,
          location: info.location,
          severity,
        });
      });
      
      console.log(`✅ Found ${this.results.outdatedPackages.length} outdated packages`);
      
    } catch (error) {
      // npm outdated returns exit code 1 when packages are outdated
      if (error.stdout) {
        try {
          const outdated = JSON.parse(error.stdout);
          Object.entries(outdated).forEach(([pkg, info]) => {
            const severity = this.getOutdatedSeverity(info.current, info.latest);
            
            this.results.outdatedPackages.push({
              package: pkg,
              current: info.current,
              wanted: info.wanted,
              latest: info.latest,
              location: info.location,
              severity,
            });
          });
        } catch (parseError) {
          console.error('❌ Failed to parse outdated packages:', parseError.message);
        }
      }
    }
  }
  
  getOutdatedSeverity(current, latest) {
    const currentParts = current.split('.').map(Number);
    const latestParts = latest.split('.').map(Number);
    
    // Major version difference
    if (latestParts[0] > currentParts[0]) {
      return 'high';
    }
    
    // Minor version difference
    if (latestParts[1] > currentParts[1]) {
      return 'moderate';
    }
    
    // Patch version difference
    if (latestParts[2] > currentParts[2]) {
      return 'low';
    }
    
    return 'info';
  }
  
  checkEnvironmentSecurity() {
    console.log('🔐 Checking environment security...');
    
    const checks = [
      {
        name: 'NODE_ENV',
        check: () => process.env.NODE_ENV === 'production',
        message: 'NODE_ENV should be set to "production" in production',
        severity: 'high',
      },
      {
        name: 'JWT_SECRET',
        check: () => {
          const secret = process.env.JWT_SECRET;
          return secret && secret.length >= 64 && secret !== 'your_jwt_secret_key_here_make_it_very_long_and_secure_for_access_tokens';
        },
        message: 'JWT_SECRET should be a strong, unique secret (64+ characters)',
        severity: 'critical',
      },
      {
        name: 'JWT_REFRESH_SECRET',
        check: () => {
          const secret = process.env.JWT_REFRESH_SECRET;
          return secret && secret.length >= 64 && secret !== process.env.JWT_SECRET;
        },
        message: 'JWT_REFRESH_SECRET should be different from JWT_SECRET and equally strong',
        severity: 'critical',
      },
      {
        name: 'MONGO_URI',
        check: () => {
          const uri = process.env.MONGO_URI;
          return uri && !uri.includes('localhost') && uri.includes('password');
        },
        message: 'MONGO_URI should use authentication and not point to localhost in production',
        severity: 'high',
      },
      {
        name: 'HTTPS',
        check: () => {
          const frontendUrl = process.env.FRONTEND_URL;
          return !frontendUrl || frontendUrl.startsWith('https://');
        },
        message: 'FRONTEND_URL should use HTTPS in production',
        severity: 'moderate',
      },
      {
        name: 'DEBUG_MODE',
        check: () => !process.env.DEBUG && !process.env.NODE_DEBUG,
        message: 'Debug mode should be disabled in production',
        severity: 'moderate',
      },
    ];
    
    checks.forEach(check => {
      const passed = check.check();
      
      this.results.environmentChecks.push({
        name: check.name,
        passed,
        message: check.message,
        severity: check.severity,
      });
      
      if (!passed) {
        this.results.summary[check.severity]++;
      }
    });
    
    console.log(`✅ Completed ${checks.length} environment security checks`);
  }
  
  checkSecurityHeaders() {
    console.log('🛡️  Checking security headers configuration...');
    
    // Read server.js to check Helmet configuration
    try {
      const serverPath = path.join(process.cwd(), 'server.js');
      const serverContent = fs.readFileSync(serverPath, 'utf8');
      
      const headerChecks = [
        {
          name: 'Helmet.js',
          check: () => serverContent.includes('helmet('),
          message: 'Helmet.js middleware should be configured',
          severity: 'high',
        },
        {
          name: 'Content Security Policy',
          check: () => serverContent.includes('contentSecurityPolicy'),
          message: 'Content Security Policy should be configured',
          severity: 'moderate',
        },
        {
          name: 'HSTS',
          check: () => serverContent.includes('hsts'),
          message: 'HTTP Strict Transport Security should be enabled',
          severity: 'moderate',
        },
        {
          name: 'X-Frame-Options',
          check: () => serverContent.includes('frameguard'),
          message: 'X-Frame-Options header should be set',
          severity: 'moderate',
        },
        {
          name: 'CORS Configuration',
          check: () => serverContent.includes('cors(') && serverContent.includes('origin'),
          message: 'CORS should be properly configured',
          severity: 'high',
        },
      ];
      
      headerChecks.forEach(check => {
        const passed = check.check();
        
        this.results.securityHeaders.push({
          name: check.name,
          passed,
          message: check.message,
          severity: check.severity,
        });
        
        if (!passed) {
          this.results.summary[check.severity]++;
        }
      });
      
    } catch (error) {
      console.error('❌ Failed to check security headers:', error.message);
    }
    
    console.log(`✅ Completed security headers check`);
  }
  
  generateRecommendations() {
    console.log('💡 Generating security recommendations...');
    
    // High-priority vulnerabilities
    const criticalVulns = this.results.vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulns.length > 0) {
      this.results.recommendations.push({
        type: 'critical-vulnerabilities',
        message: `${criticalVulns.length} critical vulnerabilities found - immediate action required`,
        severity: 'critical',
        action: 'Run "npm audit fix" or update affected packages manually',
      });
    }
    
    // Outdated packages
    const highPriorityOutdated = this.results.outdatedPackages.filter(p => p.severity === 'high');
    if (highPriorityOutdated.length > 0) {
      this.results.recommendations.push({
        type: 'outdated-packages',
        message: `${highPriorityOutdated.length} packages have major version updates available`,
        severity: 'moderate',
        action: 'Review and update packages: ' + highPriorityOutdated.map(p => p.package).join(', '),
      });
    }
    
    // Environment security
    const failedEnvChecks = this.results.environmentChecks.filter(c => !c.passed);
    if (failedEnvChecks.length > 0) {
      this.results.recommendations.push({
        type: 'environment-security',
        message: `${failedEnvChecks.length} environment security issues found`,
        severity: 'high',
        action: 'Review and fix environment configuration',
        details: failedEnvChecks.map(c => c.message),
      });
    }
    
    // General recommendations
    this.results.recommendations.push(
      {
        type: 'regular-audits',
        message: 'Schedule regular security audits',
        severity: 'info',
        action: 'Add "npm run security-audit" to your CI/CD pipeline',
      },
      {
        type: 'dependency-updates',
        message: 'Keep dependencies updated',
        severity: 'info',
        action: 'Review and update dependencies monthly',
      },
      {
        type: 'security-monitoring',
        message: 'Implement security monitoring',
        severity: 'info',
        action: 'Consider using tools like Snyk, WhiteSource, or GitHub Security Advisories',
      }
    );
  }
  
  generateReport() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `security-audit-${timestamp}`;
    
    switch (this.config.reportFormat) {
      case 'json':
        return this.generateJSONReport(filename);
      case 'html':
        return this.generateHTMLReport(filename);
      default:
        return this.generateTextReport(filename);
    }
  }
  
  generateJSONReport(filename) {
    const reportPath = path.join(this.config.outputDir, `${filename}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(this.results, null, 2));
    return reportPath;
  }
  
  generateTextReport(filename) {
    const reportPath = path.join(this.config.outputDir, `${filename}.txt`);
    
    let report = '🔒 SECURITY AUDIT REPORT\n';
    report += '========================\n\n';
    report += `Generated: ${this.results.timestamp}\n\n`;
    
    // Summary
    report += 'SUMMARY\n';
    report += '-------\n';
    report += `Critical: ${this.results.summary.critical}\n`;
    report += `High: ${this.results.summary.high}\n`;
    report += `Moderate: ${this.results.summary.moderate}\n`;
    report += `Low: ${this.results.summary.low}\n`;
    report += `Info: ${this.results.summary.info}\n\n`;
    
    // Vulnerabilities
    if (this.results.vulnerabilities.length > 0) {
      report += 'VULNERABILITIES\n';
      report += '---------------\n';
      this.results.vulnerabilities.forEach(vuln => {
        report += `${vuln.severity.toUpperCase()}: ${vuln.package}\n`;
        report += `  Title: ${vuln.title}\n`;
        report += `  Fix Available: ${vuln.fixAvailable ? 'Yes' : 'No'}\n`;
        if (vuln.url) report += `  URL: ${vuln.url}\n`;
        report += '\n';
      });
    }
    
    // Environment checks
    const failedChecks = this.results.environmentChecks.filter(c => !c.passed);
    if (failedChecks.length > 0) {
      report += 'ENVIRONMENT SECURITY ISSUES\n';
      report += '---------------------------\n';
      failedChecks.forEach(check => {
        report += `${check.severity.toUpperCase()}: ${check.name}\n`;
        report += `  ${check.message}\n\n`;
      });
    }
    
    // Recommendations
    if (this.results.recommendations.length > 0) {
      report += 'RECOMMENDATIONS\n';
      report += '---------------\n';
      this.results.recommendations.forEach(rec => {
        report += `${rec.severity.toUpperCase()}: ${rec.message}\n`;
        report += `  Action: ${rec.action}\n\n`;
      });
    }
    
    fs.writeFileSync(reportPath, report);
    return reportPath;
  }
  
  generateHTMLReport(filename) {
    const reportPath = path.join(this.config.outputDir, `${filename}.html`);
    
    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .moderate { color: #fbc02d; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
        .section { margin: 30px 0; }
        .vulnerability { background: #fff; border-left: 4px solid #ddd; padding: 15px; margin: 10px 0; }
        .vulnerability.critical { border-left-color: #d32f2f; }
        .vulnerability.high { border-left-color: #f57c00; }
        .vulnerability.moderate { border-left-color: #fbc02d; }
        .vulnerability.low { border-left-color: #388e3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Audit Report</h1>
        <p>Generated: ${this.results.timestamp}</p>
    </div>
    
    <div class="summary">
        <div class="metric critical">
            <h3>${this.results.summary.critical}</h3>
            <p>Critical</p>
        </div>
        <div class="metric high">
            <h3>${this.results.summary.high}</h3>
            <p>High</p>
        </div>
        <div class="metric moderate">
            <h3>${this.results.summary.moderate}</h3>
            <p>Moderate</p>
        </div>
        <div class="metric low">
            <h3>${this.results.summary.low}</h3>
            <p>Low</p>
        </div>
        <div class="metric info">
            <h3>${this.results.summary.info}</h3>
            <p>Info</p>
        </div>
    </div>
    
    ${this.results.vulnerabilities.length > 0 ? `
    <div class="section">
        <h2>Vulnerabilities</h2>
        ${this.results.vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity}">
            <h4>${vuln.package} (${vuln.severity})</h4>
            <p>${vuln.title}</p>
            <p><strong>Fix Available:</strong> ${vuln.fixAvailable ? 'Yes' : 'No'}</p>
            ${vuln.url ? `<p><a href="${vuln.url}" target="_blank">More Info</a></p>` : ''}
        </div>
        `).join('')}
    </div>
    ` : ''}
    
    <div class="section">
        <h2>Recommendations</h2>
        ${this.results.recommendations.map(rec => `
        <div class="vulnerability ${rec.severity}">
            <h4>${rec.message}</h4>
            <p><strong>Action:</strong> ${rec.action}</p>
        </div>
        `).join('')}
    </div>
</body>
</html>
    `;
    
    fs.writeFileSync(reportPath, html);
    return reportPath;
  }
  
  async run() {
    console.log('🔒 Starting comprehensive security audit...\n');
    
    await this.runNpmAudit();
    await this.checkOutdatedPackages();
    this.checkEnvironmentSecurity();
    this.checkSecurityHeaders();
    this.generateRecommendations();
    
    const reportPath = this.generateReport();
    
    console.log('\n📊 AUDIT SUMMARY');
    console.log('================');
    console.log(`Critical: ${this.results.summary.critical}`);
    console.log(`High: ${this.results.summary.high}`);
    console.log(`Moderate: ${this.results.summary.moderate}`);
    console.log(`Low: ${this.results.summary.low}`);
    console.log(`Info: ${this.results.summary.info}`);
    
    console.log(`\n📄 Report saved to: ${reportPath}`);
    
    // Exit with error code if critical or high severity issues found
    const hasHighPriorityIssues = this.results.summary.critical > 0 || this.results.summary.high > 0;
    if (hasHighPriorityIssues) {
      console.log('\n⚠️  High priority security issues found!');
      process.exit(1);
    } else {
      console.log('\n✅ No high priority security issues found');
      process.exit(0);
    }
  }
}

// Main execution
if (require.main === module) {
  const auditor = new SecurityAuditor(config);
  auditor.run().catch(console.error);
}

module.exports = { SecurityAuditor, config };

