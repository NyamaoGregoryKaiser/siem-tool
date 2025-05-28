import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { ArrowLeftIcon } from '@heroicons/react/24/outline';

const LogDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [log, setLog] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchLog = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.get(`/logs/${id}/`);
        setLog(response.data);
      } catch (err) {
        setError('Failed to fetch log details.');
      } finally {
        setLoading(false);
      }
    };
    fetchLog();
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <span className="text-red-400 font-bold">!</span>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <div className="mt-2 text-sm text-red-700">
              <p>{error}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!log) return null;

  return (
    <div className="max-w-2xl mx-auto bg-white rounded-lg shadow-md p-6 mt-6">
      <button
        onClick={() => navigate(-1)}
        className="mb-4 flex items-center text-blue-600 hover:text-blue-800"
      >
        <ArrowLeftIcon className="h-5 w-5 mr-1" /> Back
      </button>
      <h2 className="text-2xl font-bold mb-4">Log Details</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Object.entries(log)
          .filter(([key]) => key !== '_id')
          .map(([key, value]) => (
          <div key={key} className="border-b py-2">
            <span className="font-semibold capitalize">{key.replace(/([A-Z])/g, ' $1')}:</span>
            <span className="ml-2 text-gray-700 break-all">{String(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default LogDetail;
