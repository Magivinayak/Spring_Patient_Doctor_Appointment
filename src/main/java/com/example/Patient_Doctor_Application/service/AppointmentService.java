package com.example.Patient_Doctor_Application.service;

import com.example.Patient_Doctor_Application.entity.AppointmentEntity;
import com.example.Patient_Doctor_Application.entity.UserEntity;
import com.example.Patient_Doctor_Application.repository.AppointmentRepository;
import com.example.Patient_Doctor_Application.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AppointmentService {

    @Autowired
    private AppointmentRepository appointmentRepository;

    @Autowired
    private UserRepository userRepository;

    // Create Appointment
    public void createAppointment(AppointmentEntity appointment, Long doctorId) {
        UserEntity userEntity = userRepository.findByEmail(appointment.getEmail());
        if (userEntity != null) {
            // Use the same userId for the new appointment
            appointment.setUserId(userEntity.getId());
        }
        appointment.setDoctorId(doctorId);
        appointment.setStatus("pending");
        appointmentRepository.save(appointment);
    }

    // Count Total Appointments by Doctor ID
    public long countTotalAppointmentByDoctorId(Long id) {
        return appointmentRepository.countByDoctorId(id);
    }

    // Get All Appointments
    public List<AppointmentEntity> getAllAppointments() {
        return appointmentRepository.findAll();
    }

    // Update Status of Patient
    public AppointmentEntity updateStatusOfPatient(Long AppId) {
        Optional<AppointmentEntity> appointmentOptional = appointmentRepository.findById(AppId);
        if (appointmentOptional.isPresent()) {
            AppointmentEntity appointmentEntity = appointmentOptional.get();
            appointmentEntity.setStatus("Completed");
            return appointmentRepository.save(appointmentEntity);
        } else {
            throw new IllegalArgumentException("Appointment not found for ID: " + AppId);
        }
    }

    // Get Appointment by ID
    public Optional<AppointmentEntity> getAppointmentById(Long id) {
        return appointmentRepository.findById(id);
    }

    // Find Appointment by Patient Full Name
    public AppointmentEntity findAppointmentByFullName(String fullName) {
        return appointmentRepository.findByFullName(fullName);
    }

    // Find Appointment by Doctor ID
    public AppointmentEntity findAppointmentByDoctorId(Long doctorId) {
        return appointmentRepository.findByDoctorId(doctorId);
    }

    // Create New User
    public UserEntity createNewUser(UserEntity userEntity) {
        userEntity.setRole("ROLE_USER");
        return userRepository.save(userEntity);
    }
}
