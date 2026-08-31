export type Role = 'admin' | 'ranger' | 'citizen';
export type IncidentStatus = 'First_State' | 'Second_State' | 'Attended' | 'Rejected' | 'Citizen_Pending' | 'Approved' | 'Discarded';

export interface User {
  id: number;
  username: string;
  first_name?: string;
  last_name?: string;
  role: Role;
  whatsapp?: string;
  telegram_id?: string;
  is_active?: boolean;
}

export interface IncidentReport {
  id: number;
  tracking_code?: string;
  date_reported?: string;
  detection_time?: string;
  reporter_name?: string;
  ranger_name?: string;
  citizen_name?: string;
  citizen_email?: string;
  reporter_email?: string;
  reporter_type?: 'citizen' | 'ranger';
  source?: 'citizen' | 'ranger';
  incident_type: string;
  severity?: 'Bajo' | 'Medio' | 'Alto' | 'Crítico';
  severity_level?: 'Bajo' | 'Medio' | 'Alto' | 'Crítico';
  probable_cause?: string;
  vegetation_type?: string;
  latitude: number;
  longitude: number;
  status: IncidentStatus;
  rejection_reason?: string;
  weather_conditions?: string;
  weather_condition?: string;
  description?: string;
  photo_url?: string;
  photo_path?: string;
  photo_base64?: string;
  notifications_sent?: string[];
  notification_status?: string;
  created_at?: string;
}

export interface WeatherData {
  temperature: number;
  humidity: number;
  wind_speed: number;
  risk_index?: number;
  risk_category?: string;
}

export interface Bombero {
  id: number;
  first_name: string;
  last_name: string;
  whatsapp: string;
  unit: string;
  is_leader: boolean;
}

export interface ProjectionPoint {
  id: number;
  latitude: number;
  longitude: number;
  location_name: string;
  name?: string;
  risk_probability: number;
  risk_score?: number;
  projected_month: string;
  confidence?: number;
}

export interface AIQueryResult {
  answer: string;
  sources?: string[];
  confidence?: number;
}
