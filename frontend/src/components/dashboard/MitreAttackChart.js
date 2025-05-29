const getTechniqueLabel = (technique) => {
  const techniqueLabels = {
    'T1110.001': 'Brute Force: Password Guessing',
    'T1098': 'Account Manipulation',
    'T1218': 'Signed Binary Proxy Execution',
    'T1078': 'Valid Accounts',
    'T1059.001': 'PowerShell',
    'T1059.003': 'Windows Command Shell',
    'T1059.005': 'Visual Basic',
    'T1547.001': 'Registry Run Keys / Startup Folder',
    'T1053.005': 'Scheduled Task',
    'T1068': 'Exploitation for Privilege Escalation',
    'T1548.002': 'Bypass User Account Control',
    'T1027': 'Obfuscated Files or Information',
    'T1562.001': 'Disable or Modify Tools',
    'T1110': 'Brute Force',
    'T1110.003': 'Password Spraying',
    'T1003.001': 'LSASS Memory',
    'T1083': 'File and Directory Discovery',
    'T1018': 'Remote System Discovery',
    'T1057': 'Process Discovery',
    'T1021.001': 'Remote Desktop Protocol',
    'T1075': 'Pass the Hash',
    'T1071.001': 'Web Protocols',
    'T1105': 'Ingress Tool Transfer',
    'T1041': 'Exfiltration Over C2 Channel',
    'T1486': 'Data Encrypted for Impact',
    'T1565.001': 'Stored Data Manipulation'
  };
  return techniqueLabels[technique] || technique;
};

const getTechniqueTactic = (technique) => {
  const tacticMapping = {
    'T1110.001': 'Credential Access',
    'T1098': 'Persistence',
    'T1218': 'Defense Evasion',
    'T1078': 'Initial Access',
    'T1059.001': 'Execution',
    'T1059.003': 'Execution',
    'T1059.005': 'Execution',
    'T1547.001': 'Persistence',
    'T1053.005': 'Execution',
    'T1068': 'Privilege Escalation',
    'T1548.002': 'Privilege Escalation',
    'T1027': 'Defense Evasion',
    'T1562.001': 'Defense Evasion',
    'T1110': 'Credential Access',
    'T1110.003': 'Credential Access',
    'T1003.001': 'Credential Access',
    'T1083': 'Discovery',
    'T1018': 'Discovery',
    'T1057': 'Discovery',
    'T1021.001': 'Lateral Movement',
    'T1075': 'Lateral Movement',
    'T1071.001': 'Command and Control',
    'T1105': 'Command and Control',
    'T1041': 'Exfiltration',
    'T1486': 'Impact',
    'T1565.001': 'Impact'
  };
  return tacticMapping[technique] || 'Unknown';
}; 