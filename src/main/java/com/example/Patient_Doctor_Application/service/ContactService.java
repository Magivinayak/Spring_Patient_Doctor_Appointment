package com.example.Patient_Doctor_Application.service;

import com.example.Patient_Doctor_Application.entity.ContactEntity;
import com.example.Patient_Doctor_Application.repository.ContactRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ContactService {

    @Autowired
    private ContactRepository contactRepository;

    public ContactEntity saveContact(ContactEntity contactEntity){
        return contactRepository.save(contactEntity);
    }
}