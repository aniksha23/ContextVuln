import axios from 'axios';

const apiClient = axios.create({
    baseURL: 'http://localhost:8000/api',
    timeout: 60000,
});

export const checkBackendHealth = async () => {
    try {
        const res = await apiClient.get('/health');
        return res.data?.status === 'ok';
    } catch {
        return false;
    }
};

export const scanGithubRepository = async (repoUrl, businessCriticality) => {
    const response = await apiClient.post(
        '/scan/github',
        {
            repo_path: repoUrl,
            business_criticality: parseFloat(businessCriticality),
        },
        {
            headers: { 'Content-Type': 'application/json' },
        }
    );
    return response.data;
};

export const scanUploadedArchive = async (zipFile, businessCriticality) => {
    const formData = new FormData();
    formData.append('file', zipFile);
    formData.append('business_criticality', parseFloat(businessCriticality));

    const response = await apiClient.post('/scan/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
};