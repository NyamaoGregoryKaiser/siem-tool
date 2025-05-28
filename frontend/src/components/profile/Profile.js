import React, { useEffect, useState } from 'react';
import api from '../../services/api';
import { UserIcon, EnvelopeIcon, IdentificationIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';

const getInitials = (first, last) => {
  if (!first && !last) return '';
  return `${first?.[0] || ''}${last?.[0] || ''}`.toUpperCase();
};

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.get('/auth/profile/');
        setProfile(response.data);
      } catch (err) {
        setError('Failed to fetch profile.');
      } finally {
        setLoading(false);
      }
    };
    fetchProfile();
  }, []);

  if (loading) return <div className="p-8">Loading...</div>;
  if (error) return <div className="p-8 text-red-600">{error}</div>;
  if (!profile) return null;

  return (
    <div className="max-w-2xl mx-auto mt-12">
      <div className="bg-white rounded-xl shadow-lg p-8 flex flex-col items-center">
        {/* Avatar */}
        <div className="w-24 h-24 rounded-full bg-blue-100 flex items-center justify-center mb-4">
          <span className="text-3xl font-bold text-blue-700">
            {getInitials(profile.first_name, profile.last_name)}
          </span>
        </div>
        {/* Name and Email */}
        <h2 className="text-2xl font-bold text-gray-900 mb-1 flex items-center">
          <UserIcon className="h-6 w-6 text-blue-500 mr-2" />
          {profile.first_name} {profile.last_name}
        </h2>
        <div className="text-gray-500 flex items-center mb-2">
          <EnvelopeIcon className="h-5 w-5 mr-1" />
          {profile.email}
        </div>
        <div className="flex items-center mb-6">
          <ShieldCheckIcon className="h-5 w-5 text-green-500 mr-1" />
          <span className="text-sm font-medium text-gray-700">{profile.role?.toUpperCase()}</span>
        </div>
        {/* Details */}
        <div className="w-full grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-1">Username</div>
            <div className="font-medium text-gray-800">{profile.username}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-1">Active</div>
            <div className="font-medium text-gray-800">{profile.is_active ? 'Yes' : 'No'}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-1">Created At</div>
            <div className="font-medium text-gray-800">{new Date(profile.created_at).toLocaleString()}</div>
          </div>
          <div className="bg-gray-50 rounded-lg p-4">
            <div className="text-xs text-gray-400 mb-1">User ID</div>
            <div className="font-mono text-gray-700 text-xs break-all">{profile.id}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile; 