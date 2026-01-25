const roles = {
    DOCTOR: 'doctor', 
    NURSE: 'nurse', 
    PATIENT: 'patient'
};

const accessControlMatrix = {
    '/createRecord': [roles.DOCTOR], 
    '/viewRecord': [roles.DOCTOR, roles.NURSE], 
    'myRecord': [roles.PATIENT]
};

module.exports = { roles, accessControlMatrix };