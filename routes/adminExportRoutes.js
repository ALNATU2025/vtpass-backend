const express = require('express');
const router = express.Router();
const Transaction = require('../models/Transaction');
const User = require('../models/User');

// Helper function to format currency
const formatCurrency = (amount) => `₦${(amount || 0).toFixed(2)}`;

// @desc    Export transactions to CSV/Excel
// @route   GET /api/admin/export-transactions/excel
// @access  Private/Admin
router.get('/excel', async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    const businessName = 'DALABAPAY';
    
    const query = {};
    if (startDate && endDate) {
      query.createdAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
    }
    if (status && status !== 'all') query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'fullName email phone')
      .sort({ createdAt: -1 })
      .lean();
    
    // Create CSV headers
    const headers = [
      'Transaction ID', 'Reference', 'Type', 'Amount', 'Status', 
      'User Name', 'User Email', 'User Phone', 'Date', 'Description'
    ];
    
    const rows = transactions.map(tx => [
      tx._id.toString(),
      tx.reference || 'N/A',
      tx.type || 'N/A',
      formatCurrency(tx.amount),
      tx.status || 'unknown',
      tx.userId?.fullName || 'N/A',
      tx.userId?.email || 'N/A',
      tx.userId?.phone || 'N/A',
      new Date(tx.createdAt).toLocaleString(),
      tx.description || 'N/A'
    ]);
    
    // Build CSV content
    const csvContent = [
      `"${businessName} Transaction Report"`,
      `"Generated: ${new Date().toLocaleString()}"`,
      `"Total Records: ${transactions.length}"`,
      '',
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${businessName.toLowerCase()}_transactions_${Date.now()}.csv"`);
    res.send('\uFEFF' + csvContent);
    
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// @desc    Export to Word (HTML format)
// @route   GET /api/admin/export-transactions/word
// @access  Private/Admin
router.get('/word', async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    const businessName = 'DALABAPAY';
    
    const query = {};
    if (startDate && endDate) {
      query.createdAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
    }
    if (status && status !== 'all') query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'fullName email phone')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalAmount = transactions.reduce((sum, tx) => sum + (tx.amount || 0), 0);
    
    const html = `<!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>${businessName} Transaction Report</title>
      <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #2c3e50; padding-bottom: 20px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 28px; }
        .header h2 { color: #666; margin: 5px 0 0; font-size: 16px; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .summary table { width: auto; margin: 0 auto; }
        .summary td { padding: 5px 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #2c3e50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .footer { margin-top: 30px; text-align: center; font-size: 11px; color: #666; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>${businessName}</h1>
        <h2>Transaction Report</h2>
        <p>Generated: ${new Date().toLocaleString()}</p>
      </div>
      
      <div class="summary">
        <table>
          <tr><th colspan="2">Report Summary</th></tr>
          <tr><td><strong>Total Transactions:</strong></td><td>${transactions.length}</td></tr>
          <tr><td><strong>Total Amount:</strong></td><td>${formatCurrency(totalAmount)}</td></tr>
          <tr><td><strong>Date Range:</strong></td><td>${startDate || 'All'} to ${endDate || 'Present'}</td></tr>
        </table>
      </div>
      
      <table>
        <thead>
          <tr>
            <th>Transaction ID</th><th>Reference</th><th>Type</th><th>Amount</th>
            <th>Status</th><th>User Name</th><th>User Email</th><th>Date</th>
          </tr>
        </thead>
        <tbody>
          ${transactions.map(tx => `
            <tr>
              <td>${tx._id.toString().slice(-8)}</td>
              <td>${tx.reference || 'N/A'}</td>
              <td>${tx.type || 'N/A'}</td>
              <td>${formatCurrency(tx.amount)}</td>
              <td>${tx.status || 'unknown'}</td>
              <td>${tx.userId?.fullName || 'N/A'}</td>
              <td>${tx.userId?.email || 'N/A'}</td>
              <td>${new Date(tx.createdAt).toLocaleDateString()}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      
      <div class="footer">
        <p>${businessName} - Official Transaction Report</p>
        <p>This document is system-generated and requires no signature.</p>
      </div>
    </body>
    </html>`;
    
    res.setHeader('Content-Type', 'application/msword');
    res.setHeader('Content-Disposition', `attachment; filename="${businessName.toLowerCase()}_report_${Date.now()}.doc"`);
    res.send(html);
    
  } catch (error) {
    console.error('Word export error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// @desc    Export to PDF (HTML format, browser print)
// @route   GET /api/admin/export-transactions/pdf
// @access  Private/Admin
router.get('/pdf', async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    const businessName = 'DALABAPAY';
    
    const query = {};
    if (startDate && endDate) {
      query.createdAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
    }
    if (status && status !== 'all') query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'fullName email phone')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalAmount = transactions.reduce((sum, tx) => sum + (tx.amount || 0), 0);
    
    const html = `<!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>${businessName} Transaction Report</title>
      <style>
        @media print {
          body { margin: 0; padding: 20px; }
          .page-break { page-break-before: always; }
        }
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #2c3e50; padding-bottom: 20px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 28px; }
        .header p { color: #666; margin: 5px 0 0; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .summary table { width: 100%; max-width: 500px; margin: 0 auto; }
        .summary td { padding: 5px 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #2c3e50; color: white; }
        .footer { margin-top: 30px; text-align: center; font-size: 10px; color: #666; }
        .status-success { color: green; font-weight: bold; }
        .status-pending { color: orange; font-weight: bold; }
        .status-failed { color: red; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>${businessName}</h1>
        <p>Official Transaction Report</p>
        <p>Generated: ${new Date().toLocaleString()}</p>
      </div>
      
      <div class="summary">
        <table>
          <tr><th>Total Transactions:</th><td>${transactions.length}</td></tr>
          <tr><th>Total Amount:</th><td>${formatCurrency(totalAmount)}</td></tr>
          <tr><th>Date Range:</th><td>${startDate || 'All Time'} to ${endDate || 'Present'}</td></tr>
          <tr><th>Business Name:</th><td>${businessName}</td></tr>
        </table>
      </div>
      
      <table>
        <thead>
          <tr>
            <th>#</th><th>Date</th><th>Type</th><th>Amount</th><th>Status</th><th>User</th>
          </tr>
        </thead>
        <tbody>
          ${transactions.map((tx, idx) => `
            <tr>
              <td>${idx + 1}</td>
              <td>${new Date(tx.createdAt).toLocaleDateString()}</td>
              <td>${tx.type || 'N/A'}</td>
              <td>${formatCurrency(tx.amount)}</td>
              <td class="status-${tx.status}">${tx.status || 'unknown'}</td>
              <td>${tx.userId?.fullName || 'N/A'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      
      <div class="footer">
        <p>This is an official document from ${businessName}. All rights reserved.</p>
        <p>Report ID: ${businessName.toLowerCase()}_${Date.now()}</p>
      </div>
    </body>
    </html>`;
    
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="${businessName.toLowerCase()}_report_${Date.now()}.html"`);
    res.send(html);
    
  } catch (error) {
    console.error('PDF export error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
