package com.example.Patient_Doctor_Application.controller;

import com.example.Patient_Doctor_Application.entity.AppointmentEntity;
import com.example.Patient_Doctor_Application.entity.CommentEntity;
import com.example.Patient_Doctor_Application.entity.DoctorEntity;
import com.example.Patient_Doctor_Application.service.AppointmentService;
import com.example.Patient_Doctor_Application.service.CommentService;
import com.example.Patient_Doctor_Application.service.DoctorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;



@Controller
public class DoctorController {

    @Autowired
    private DoctorService doctorService;

    @Autowired
    private AppointmentService appointmentService;

    @Autowired
    private CommentService commentService;

    // Doctor Login Page
    @GetMapping("/docLogin")
    public String doctorLogin(Model model) {
        model.addAttribute("doctorEntity", new DoctorEntity());
        return "doctorLogin";
    }

    // Doctor Login Data Processing
    @PostMapping("/doctorLogin")
    public String doctorLoginData(@ModelAttribute("doctorEntity") DoctorEntity doctorEntity, RedirectAttributes redirectAttributes) {
        try {
            DoctorEntity foundDoctor = doctorService.findDoctorByEmail(doctorEntity.getEmail());
            if (foundDoctor != null && foundDoctor.getPassword().equals(doctorEntity.getPassword())) {
                redirectAttributes.addFlashAttribute("email", doctorEntity.getEmail());
                return "redirect:/doctorHome";
            } else {
                redirectAttributes.addFlashAttribute("error", "Invalid email or password");
                return "redirect:/docLogin";
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while login doctor");
            return "redirect:/errorPage";
        }
    }

    // Doctor Registration Page
    @GetMapping("/doctorRegister")
    public String doctorRegister(Model model) {
        model.addAttribute("doctorEntity", new DoctorEntity());
        return "doctorRegister";
    }

    // Doctor Registration Data Processing
    @PostMapping("/saveDoctor")
    public String addDoctor(@ModelAttribute("doctorEntity") DoctorEntity doctorEntity, RedirectAttributes redirectAttributes) {
        try {
            doctorService.registerDoctor(doctorEntity);
            redirectAttributes.addFlashAttribute("email", doctorEntity.getEmail());
            return "redirect:/doctorHome";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while saving the doctor details");
            return "redirect:/errorPage";
        }
    }

    // Doctor Home Page
    @GetMapping("/doctorHome")
    public String doctorDashboard(@ModelAttribute("email") String email, Model model,RedirectAttributes redirectAttributes) {
        try {
            DoctorEntity doctorEntity = doctorService.findDoctorByEmail(email);
            if (doctorEntity == null) {
                return "redirect:/docLogin";
            }
            AppointmentEntity appointmentEntity = appointmentService.findAppointmentByDoctorId(doctorEntity.getDoctorId());
            long totalDoctors = doctorService.countTotalDoctor();
            long totalAppointments = appointmentService.countTotalAppointmentByDoctorId(doctorEntity.getDoctorId());
            CommentEntity commentEntity = new CommentEntity();
            model.addAttribute("totalDoctors", totalDoctors);
            model.addAttribute("totalAppointments", totalAppointments);
            model.addAttribute("appointments", appointmentEntity);
            model.addAttribute("commentUpdate", commentEntity);
            model.addAttribute("doctorId", doctorEntity.getDoctorId());
            return "doctorHome";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while loading Doctor Dashboard");
            return "redirect:/errorPage";
        }
    }

    // Update Doctor Page
    @GetMapping("/updateDoc/{id}")
    public String updateDoctor(@PathVariable("id") Long id, Model model,RedirectAttributes redirectAttributes) {
        try {
            Optional<DoctorEntity> optionalDoctorEntity = doctorService.getDoctorById(id);
            if (optionalDoctorEntity.isPresent()) {
                DoctorEntity doctorEntity = optionalDoctorEntity.get();
                model.addAttribute("updatedDoc", doctorEntity);
                return "doctorUpdate";
            } else {
                return "doctorHome";
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while loading doctor update page");
            return "redirect:/errorPage";
        }
    }

    // Update Doctor Data Processing
    @PostMapping("/updateDoctor")
    public String updateDoctorData(@ModelAttribute("updatedDoc") DoctorEntity doctorEntity, RedirectAttributes redirectAttributes) {
        try {
            Long id = doctorEntity.getDoctorId();
            doctorService.updateDoctorById(id, doctorEntity);
            redirectAttributes.addFlashAttribute("email", doctorEntity.getEmail());
            return "redirect:/doctorHome";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while Updating the Doctor Details");
            return "redirect:/errorPage";
        }
    }

    // Save Comment Data Processing
    @PostMapping("/saveComment")
    public String saveComment(@ModelAttribute("commentUpdate") CommentEntity commentEntity, RedirectAttributes redirectAttributes) {
        try {

            List<AppointmentEntity> appointmentEntities = appointmentService.getAllAppointments();

            // Filter appointments by patient name
            List<AppointmentEntity> filteredAppointments = appointmentEntities.stream()
                    .filter(appointment -> appointment.getFullName().equalsIgnoreCase(commentEntity.getPatientName()))
                    .filter(appointment -> appointment.getDoctorName().equalsIgnoreCase(commentEntity.getDoctorName()))
                    .filter(appointment -> appointment.getDiseases().equalsIgnoreCase(commentEntity.getDisease()))
                    .toList();
            AppointmentEntity appointmentEntity=filteredAppointments.get(0);

            if (appointmentEntity != null) {
                commentEntity.setUserId(appointmentEntity.getUserId());
                commentEntity.setEmail(appointmentEntity.getEmail());
                appointmentService.updateStatusOfPatient(appointmentEntity.getAppId());
                commentService.saveComment(commentEntity);
                Optional<DoctorEntity> optionalDoctorEntity = doctorService.getDoctorById(appointmentEntity.getDoctorId());
                if (optionalDoctorEntity.isPresent()) {
                    DoctorEntity doctorEntity = optionalDoctorEntity.get();
                    redirectAttributes.addFlashAttribute("email", doctorEntity.getEmail());
                }
            }
            return "redirect:/doctorHome";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage","Error occurred while Saving Comment/Prescription");
            return "redirect:/errorPage";
        }
    }
}
