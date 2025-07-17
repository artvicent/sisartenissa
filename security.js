// Módulo de seguridad mejorado con logging estadístico completo

class SecurityManager {
  constructor() {
    this.loginAttempts = JSON.parse(localStorage.getItem("loginAttempts")) || {}
    this.maxLoginAttempts = 5
    this.lockoutTime = 15 * 60 * 1000 // 15 minutos
    this.activityLog = JSON.parse(localStorage.getItem("securityLog")) || []

    // Nuevo: Log estadístico de usuarios
    this.userActivityLog = JSON.parse(localStorage.getItem("userActivityLog")) || []
    this.currentSessionLog = null

    // Inicializar salt si no existe
    if (!localStorage.getItem("securitySalt")) {
      const salt = this.generateRandomString(16)
      localStorage.setItem("securitySalt", salt)
    }
    this.salt = localStorage.getItem("securitySalt")
  }

  // Nuevo: Iniciar sesión de actividad de usuario
  startUserSession(username, role) {
    this.currentSessionLog = {
      sessionId: this.generateRandomString(12),
      username: username,
      role: role,
      loginTime: new Date().toISOString(),
      logoutTime: null,
      activities: [],
      totalTimeSpent: 0,
      sectionsVisited: [],
      actionsPerformed: 0,
    }

    this.logUserActivity("LOGIN", "Usuario inició sesión", {
      userAgent: navigator.userAgent,
      timestamp: new Date().toISOString(),
    })
  }

  // Nuevo: Registrar actividad del usuario
  logUserActivity(action, description, additionalData = {}) {
    if (!this.currentSessionLog) return

    const activity = {
      timestamp: new Date().toISOString(),
      action: action,
      description: description,
      section: additionalData.section || "unknown",
      details: additionalData,
    }

    this.currentSessionLog.activities.push(activity)
    this.currentSessionLog.actionsPerformed++

    // Registrar sección visitada si es nueva
    if (additionalData.section && !this.currentSessionLog.sectionsVisited.includes(additionalData.section)) {
      this.currentSessionLog.sectionsVisited.push(additionalData.section)
    }

    this.saveUserActivityLog()
  }

  // Nuevo: Finalizar sesión de usuario
  endUserSession() {
    if (!this.currentSessionLog) return

    this.currentSessionLog.logoutTime = new Date().toISOString()

    // Calcular tiempo total de sesión
    const loginTime = new Date(this.currentSessionLog.loginTime)
    const logoutTime = new Date(this.currentSessionLog.logoutTime)
    this.currentSessionLog.totalTimeSpent = Math.round((logoutTime - loginTime) / 1000) // en segundos

    this.logUserActivity("LOGOUT", "Usuario cerró sesión", {
      sessionDuration: this.currentSessionLog.totalTimeSpent,
      totalActions: this.currentSessionLog.actionsPerformed,
      sectionsVisited: this.currentSessionLog.sectionsVisited.length,
    })

    // Guardar sesión completa en el log histórico
    this.userActivityLog.push({ ...this.currentSessionLog })

    // Mantener solo las últimas 100 sesiones
    if (this.userActivityLog.length > 100) {
      this.userActivityLog = this.userActivityLog.slice(-100)
    }

    this.saveUserActivityLog()
    this.currentSessionLog = null
  }

  // Nuevo: Obtener estadísticas de usuario
  getUserStatistics(username = null, days = 30) {
    const cutoffDate = new Date()
    cutoffDate.setDate(cutoffDate.getDate() - days)

    const sessions = this.userActivityLog.filter((session) => {
      const sessionDate = new Date(session.loginTime)
      return sessionDate >= cutoffDate && (username ? session.username === username : true)
    })

    const stats = {
      totalSessions: sessions.length,
      totalTimeSpent: sessions.reduce((sum, s) => sum + (s.totalTimeSpent || 0), 0),
      averageSessionTime: 0,
      totalActions: sessions.reduce((sum, s) => sum + (s.actionsPerformed || 0), 0),
      mostVisitedSections: {},
      mostActiveUsers: {},
      sessionsByDay: {},
      averageActionsPerSession: 0,
    }

    if (stats.totalSessions > 0) {
      stats.averageSessionTime = Math.round(stats.totalTimeSpent / stats.totalSessions)
      stats.averageActionsPerSession = Math.round(stats.totalActions / stats.totalSessions)
    }

    // Analizar secciones más visitadas
    sessions.forEach((session) => {
      session.sectionsVisited.forEach((section) => {
        stats.mostVisitedSections[section] = (stats.mostVisitedSections[section] || 0) + 1
      })

      // Usuarios más activos
      stats.mostActiveUsers[session.username] = (stats.mostActiveUsers[session.username] || 0) + 1

      // Sesiones por día
      const day = session.loginTime.split("T")[0]
      stats.sessionsByDay[day] = (stats.sessionsByDay[day] || 0) + 1
    })

    return stats
  }

  // Nuevo: Guardar log de actividad de usuarios
  saveUserActivityLog() {
    localStorage.setItem("userActivityLog", JSON.stringify(this.userActivityLog))
  }

  // Verificar si un usuario está bloqueado
  isUserLocked(username) {
    const attempts = this.loginAttempts[username]
    if (!attempts) return false

    if (attempts.count >= this.maxLoginAttempts && Date.now() - attempts.lastAttempt < this.lockoutTime) {
      return true
    }

    // Si el tiempo de bloqueo ha pasado, reiniciar contador
    if (attempts.count >= this.maxLoginAttempts && Date.now() - attempts.lastAttempt >= this.lockoutTime) {
      this.loginAttempts[username] = { count: 0, lastAttempt: 0 }
      this.saveLoginAttempts()
    }

    return false
  }

  // Registrar intento fallido de login
  registerFailedAttempt(username) {
    if (!this.loginAttempts[username]) {
      this.loginAttempts[username] = { count: 0, lastAttempt: 0 }
    }

    this.loginAttempts[username].count += 1
    this.loginAttempts[username].lastAttempt = Date.now()
    this.saveLoginAttempts()

    this.logSecurityEvent({
      type: "LOGIN_FAILED",
      username: username,
      timestamp: new Date().toISOString(),
      details: "Intento fallido " + this.loginAttempts[username].count + " de " + this.maxLoginAttempts,
    })

    if (this.loginAttempts[username].count >= this.maxLoginAttempts) {
      this.logSecurityEvent({
        type: "ACCOUNT_LOCKED",
        username: username,
        timestamp: new Date().toISOString(),
        details: "Cuenta bloqueada por " + this.lockoutTime / 60000 + " minutos",
      })
    }
  }

  // Reiniciar contador de intentos fallidos
  resetFailedAttempts(username) {
    if (this.loginAttempts[username]) {
      this.loginAttempts[username].count = 0
      this.saveLoginAttempts()
    }
  }

  // Guardar intentos de login
  saveLoginAttempts() {
    localStorage.setItem("loginAttempts", JSON.stringify(this.loginAttempts))
  }

  // Hash simple pero funcional (mejorado)
  simpleHash(str) {
    var hash = 0
    if (str.length === 0) return hash.toString()

    for (var i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i)
      hash = (hash << 5) - hash + char
      hash = hash & hash // Convertir a entero de 32 bits
    }
    return Math.abs(hash).toString(16)
  }

  // Generar hash de contraseña
  hashPassword(password) {
    return this.simpleHash(password + this.salt)
  }

  // Generar token de sesión
  generateSessionToken(username, role) {
    const timestamp = Date.now()
    const randomPart = this.generateRandomString(8)
    const dataToHash = username + "|" + role + "|" + timestamp + "|" + randomPart + "|" + this.salt
    const hash = this.simpleHash(dataToHash)

    return {
      token: hash + "." + timestamp + "." + randomPart,
      expires: timestamp + 8 * 60 * 60 * 1000, // 8 horas
    }
  }

  // Validar token de sesión
  validateSessionToken(token, username, role) {
    if (!token) return false

    try {
      const parts = token.split(".")
      if (parts.length !== 3) return false

      const hash = parts[0]
      const timestamp = parts[1]
      const randomPart = parts[2]
      const dataToHash = username + "|" + role + "|" + timestamp + "|" + randomPart + "|" + this.salt
      const expectedHash = this.simpleHash(dataToHash)

      // Verificar hash y expiración
      const isValidHash = hash === expectedHash
      const isNotExpired = Number.parseInt(timestamp) + 8 * 60 * 60 * 1000 > Date.now()

      return isValidHash && isNotExpired
    } catch (error) {
      console.error("Error validating session token:", error)
      return false
    }
  }

  // Generar string aleatorio
  generateRandomString(length) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    var result = ""

    for (var i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }

    return result
  }

  // Registrar evento de seguridad
  logSecurityEvent(event) {
    this.activityLog.push(event)

    // Mantener el log a un tamaño manejable
    if (this.activityLog.length > 1000) {
      this.activityLog = this.activityLog.slice(-1000)
    }

    localStorage.setItem("securityLog", JSON.stringify(this.activityLog))
  }

  // Sanitizar entrada para prevenir XSS
  sanitizeInput(input) {
    if (typeof input !== "string") return input

    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;")
  }

  // Validar datos de entrada
  validateInput(input, type) {
    switch (type) {
      case "username":
        return /^[a-zA-Z0-9_]{3,20}$/.test(input)
      case "name":
        return /^[a-zA-Z0-9 áéíóúÁÉÍÓÚñÑ.,]{2,50}$/.test(input)
      case "number":
        return !isNaN(Number.parseFloat(input)) && isFinite(input)
      case "email":
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)
      default:
        return true
    }
  }
}

// Hacer disponible globalmente
window.SecurityManager = SecurityManager
