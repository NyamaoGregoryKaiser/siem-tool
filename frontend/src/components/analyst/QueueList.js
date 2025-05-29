import React, { useState, useEffect } from 'react';
import {
  ClockIcon,
  UserIcon,
  FlagIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationCircleIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import api from '../../services/api';

const QueueList = () => {
  const [queueItems, setQueueItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [removing, setRemoving] = useState({});

  const fetchQueueItems = async () => {
    try {
      setLoading(true);
      const response = await api.get('/logs/analyst-queue/');
      setQueueItems(response.data);
    } catch (error) {
      console.error('Error fetching queue items:', error);
      setError(error.response?.data?.message || 'Failed to fetch queue items');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueueItems();
    // Refresh queue items every minute
    const intervalId = setInterval(fetchQueueItems, 60000);
    return () => clearInterval(intervalId);
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'investigating':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'resolved':
        return 'bg-green-100 text-green-800 border-green-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high':
        return 'text-red-600';
      case 'medium':
        return 'text-orange-600';
      case 'low':
        return 'text-green-600';
      default:
        return 'text-gray-600';
    }
  };

  const handleStatusChange = async (queueId, newStatus, logDetails) => {
    try {
      await api.put(`/logs/analyst-queue/${queueId}/`, {
        status: newStatus
      });
      if (newStatus === 'investigating') {
        setSelectedLog(logDetails);
      }
      fetchQueueItems();
    } catch (error) {
      console.error('Error updating status:', error);
      setError(error.response?.data?.message || 'Failed to update status');
    }
  };

  const handleRemoveFromQueue = async (queueId) => {
    if (!window.confirm('Are you sure you want to remove this item from the investigation queue?')) {
      return;
    }

    try {
      setRemoving(prev => ({ ...prev, [queueId]: true }));
      await api.delete(`/logs/analyst-queue/${queueId}/delete/`);
      // Remove the item from the state
      setQueueItems(prev => prev.filter(item => item._id !== queueId));
    } catch (error) {
      console.error('Error removing from queue:', error);
      setError(error.response?.data?.message || 'Failed to remove from queue');
    } finally {
      setRemoving(prev => ({ ...prev, [queueId]: false }));
    }
  };

  const LogDetailsModal = ({ log, onClose }) => {
    if (!log) return null;

    return (
      <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center p-4 z-50">
        <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
          <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900">Log Details</h3>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-500"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>
          <div className="px-6 py-4">
            <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <dt className="text-sm font-medium text-gray-500">Message</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.Message}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Event ID</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.EventID}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Event Type</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.EventType}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Computer Name</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.ComputerName}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Source IP</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.SourceIP}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Operating System</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.OperatingSystem}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Time Generated</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.TimeGenerated}</dd>
              </div>
              <div>
                <dt className="text-sm font-medium text-gray-500">Level</dt>
                <dd className="mt-1 text-sm text-gray-900">{log.Level}</dd>
              </div>
              {log.AccountName && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Account Name</dt>
                  <dd className="mt-1 text-sm text-gray-900">{log.AccountName}</dd>
                </div>
              )}
              {log.AccountSID && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">Account SID</dt>
                  <dd className="mt-1 text-sm text-gray-900">{log.AccountSID}</dd>
                </div>
              )}
              {log.Technique && (
                <div>
                  <dt className="text-sm font-medium text-gray-500">MITRE Technique</dt>
                  <dd className="mt-1 text-sm text-gray-900">{log.Technique}</dd>
                </div>
              )}
            </dl>
          </div>
          <div className="px-6 py-4 border-t border-gray-200 flex justify-end">
            <button
              onClick={onClose}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="md:flex md:items-center md:justify-between">
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl">
            Analyst Queue
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            Review and investigate suspicious security events
          </p>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <ExclamationCircleIcon className="h-5 w-5 text-red-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>{error}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Queue Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Time Added
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Priority
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Added By
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Log Details
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {queueItems.map((item) => (
                    <tr key={item._id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <div className="flex items-center">
                          <ClockIcon className="h-4 w-4 text-gray-400 mr-2" />
                          {new Date(item.added_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(item.status)}`}>
                          {item.status}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <div className={`flex items-center ${getPriorityColor(item.priority)}`}>
                          <FlagIcon className="h-4 w-4 mr-2" />
                          {item.priority}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <div className="flex items-center">
                          <UserIcon className="h-4 w-4 text-gray-400 mr-2" />
                          {item.added_by}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-900">
                        {item.log_details?.Message || 'No details available'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        {item.status !== 'resolved' && (
                          <div className="flex space-x-2">
                            {item.status === 'pending' && (
                              <button
                                onClick={() => handleStatusChange(item._id, 'investigating', item.log_details)}
                                className="text-blue-600 hover:text-blue-900"
                              >
                                Start Investigation
                              </button>
                            )}
                            {item.status === 'investigating' && (
                              <button
                                onClick={() => handleStatusChange(item._id, 'resolved')}
                                className="text-green-600 hover:text-green-900"
                              >
                                <CheckCircleIcon className="h-5 w-5" />
                              </button>
                            )}
                            <button
                              onClick={() => handleRemoveFromQueue(item._id)}
                              disabled={removing[item._id]}
                              className="text-gray-600 hover:text-gray-900 disabled:opacity-50"
                              title="Remove from investigation"
                            >
                              <XMarkIcon className="h-5 w-5" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {queueItems.length === 0 && (
              <div className="text-center py-12">
                <ExclamationCircleIcon className="h-12 w-12 text-gray-300 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No items in queue</h3>
                <p className="text-gray-500">The analyst queue is currently empty.</p>
              </div>
            )}
          </>
        )}
      </div>

      {/* Log Details Modal */}
      {selectedLog && (
        <LogDetailsModal
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
        />
      )}
    </div>
  );
};

export default QueueList; 