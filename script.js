// Sistema de Charcutería - Versión mejorada con logging estadístico y numeración correlativa

// Clases del Sistema
class Company {
  constructor() {
    this.name = localStorage.getItem("companyName") || "Mi Charcutería"
    this.rif = localStorage.getItem("companyRif") || "J-12345678-9"
    this.logo = localStorage.getItem("companyLogo") || ""
    this.address = localStorage.getItem("companyAddress") || "Av. Principal #123, Ciudad"
  }

  updateInfo(name, rif, logo, address) {
    this.name = name
    this.rif = rif
    this.logo = logo
    this.address = address
    localStorage.setItem("companyName", name)
    localStorage.setItem("companyRif", rif)
    localStorage.setItem("companyLogo", logo)
    localStorage.setItem("companyAddress", address)
    this.updateUI()
  }

  updateUI() {
    // Actualizar nombres de empresa
    const companyNameEl = document.getElementById("companyName")
    const navCompanyNameEl = document.getElementById("navCompanyName")

    if (companyNameEl) companyNameEl.textContent = this.name
    if (navCompanyNameEl) navCompanyNameEl.textContent = this.name

    // Actualizar logos
    this.updateLogos()
  }

  updateLogos() {
    // Logos en pantalla de login
    const loginLogoImg = document.getElementById("companyLogoImg")
    const loginLogoSvg = document.getElementById("companyLogoSvg")

    // Logos en navbar
    const navLogoImg = document.getElementById("navLogoImg")
    const navLogoSvg = document.getElementById("navLogoSvg")

    if (this.logo && this.logo.trim() !== "") {
      // Mostrar imagen personalizada
      if (loginLogoImg) {
        loginLogoImg.src = this.logo
        loginLogoImg.style.display = "block"
        loginLogoImg.onerror = function () {
          this.style.display = "none"
          if (loginLogoSvg) loginLogoSvg.style.display = "block"
        }
      }
      if (loginLogoSvg) loginLogoSvg.style.display = "none"

      if (navLogoImg) {
        navLogoImg.src = this.logo
        navLogoImg.style.display = "block"
        navLogoImg.onerror = function () {
          this.style.display = "none"
          if (navLogoSvg) navLogoSvg.style.display = "block"
        }
      }
      if (navLogoSvg) navLogoSvg.style.display = "none"
    } else {
      // Mostrar SVG por defecto
      if (loginLogoImg) loginLogoImg.style.display = "none"
      if (loginLogoSvg) loginLogoSvg.style.display = "block"
      if (navLogoImg) navLogoImg.style.display = "none"
      if (navLogoSvg) navLogoSvg.style.display = "block"
    }
  }
}

class User {
  constructor(username, password, role) {
    this.username = username
    this.password = password
    this.role = role
    this.lastLogin = null
    this.failedLoginAttempts = 0
    this.locked = false
    this.passwordLastChanged = new Date()
    this.passwordExpiryDays = 90
  }

  recordSuccessfulLogin() {
    this.lastLogin = new Date()
    this.failedLoginAttempts = 0
  }

  recordFailedLogin() {
    this.failedLoginAttempts += 1
    if (this.failedLoginAttempts >= 5) {
      this.locked = true
    }
  }

  isPasswordExpired() {
    if (!this.passwordExpiryDays) return false
    const today = new Date()
    const lastChanged = new Date(this.passwordLastChanged)
    const diffTime = Math.abs(today - lastChanged)
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays > this.passwordExpiryDays
  }
}

class UserManager {
  constructor(securityManager) {
    this.securityManager = securityManager || new window.SecurityManager()
    const savedUsers = localStorage.getItem("systemUsers")
    if (savedUsers) {
      const usersData = JSON.parse(savedUsers)
      this.users = usersData.map((userData) => {
        const user = new User(userData.username, userData.password, userData.role)
        user.lastLogin = userData.lastLogin ? new Date(userData.lastLogin) : null
        return user
      })
    } else {
      this.users = [
        new User("admin", "admin123", "admin"),
        new User("administrador", "admin123", "administrador"),
        new User("vendedor", "vend123", "vendedor"),
      ]
      this.saveUsers()
    }
    this.currentUser = null
    this.sessionToken = null
  }
  loadUsers() {
  const raw = JSON.parse(localStorage.getItem("systemUsers")) || [];
  return raw.map((u) => new User(
    u.username,
    u.password,
    u.role,
    new Date(u.lastLogin),
    new Date(u.passwordLastChanged),
    u.passwordExpiryDays,
    u.locked,
    u.failedLoginAttempts
  ));
}

  saveUsers() {
    const usersData = this.users.map((user) => ({
      username: user.username,
      password: user.password,
      role: user.role,
      lastLogin: user.lastLogin ? user.lastLogin.toISOString() : null,
      passwordLastChanged: user.passwordLastChanged ? user.passwordLastChanged.toISOString() : new Date().toISOString(),
      passwordExpiryDays: user.passwordExpiryDays || 90,
      locked: user.locked || false,
      failedLoginAttempts: user.failedLoginAttempts || 0,
    }))
    localStorage.setItem("systemUsers", JSON.stringify(usersData))
  }

  addUser(username, password, role = "usuario") {
  if (this.users.find((u) => u.username === username)) {
    return { success: false, message: "El usuario ya existe" };
  }

  const newUser = new User(username, password, role);
  this.users.push(newUser);
  this.saveUsers();

  // 🔄 Refrescamos desde localStorage por consistencia
  this.users = this.loadUsers();

  return { success: true, message: "Usuario agregado exitosamente" };
  }
  deleteUser(username) {
  const index = this.users.findIndex((u) => u.username === username);
  if (index === -1) {
    return { success: false, message: "Usuario no encontrado" };
  }

  this.users.splice(index, 1);
  this.saveUsers();

  // 🔄 Refrescamos desde localStorage
  this.users = this.loadUsers();

  return { success: true, message: `Usuario "${username}" eliminado correctamente.` };
  }

  changePassword(username, newPassword) {
    const user = this.users.find((u) => u.username === username)
    if (!user) {
      return { success: false, message: "Usuario no encontrado" }
    }
    
    if (newPassword.length > 12) {
      return { success: false, message: "La contraseña no debe exceder los 12 caracteres" }
    }
    const hasUpperCase = /[A-Z]/.test(newPassword)
    const hasLowerCase = /[a-z]/.test(newPassword)
    const hasNumbers = /[0-9]/.test(newPassword)
    const hasSpecialChars = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(newPassword)
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChars) {
      return {
        success: false,
        message: "La contraseña debe incluir mayúsculas, minúsculas, números y caracteres especiales",
        validation: { hasUpperCase, hasLowerCase, hasNumbers, hasSpecialChars },
      }
    }
    user.password = newPassword
    user.passwordLastChanged = new Date()
    this.saveUsers()
    this.securityManager.logSecurityEvent({
      type: "PASSWORD_CHANGED",
      username: username,
      timestamp: new Date().toISOString(),
      details: "Contraseña cambiada exitosamente",
    })
    return { success: true, message: "Contraseña cambiada exitosamente" }
  }

  unlockUser(username) {
    const user = this.users.find((u) => u.username === username)
    if (!user) {
      return { success: false, message: "Usuario no encontrado" }
    }
    user.locked = false
    user.failedLoginAttempts = 0
    this.saveUsers()
    this.securityManager.resetFailedAttempts(username)
    this.securityManager.logSecurityEvent({
      type: "USER_UNLOCKED",
      username: username,
      timestamp: new Date().toISOString(),
      details: "Usuario desbloqueado por administrador",
    })
    return { success: true, message: "Usuario desbloqueado exitosamente" }
  }
  authenticate(username, password) {
    console.log("Intentando autenticar:", username)
    if (this.securityManager.isUserLocked(username)) {
      this.securityManager.logSecurityEvent({
        type: "LOGIN_BLOCKED",
        username: username,
        timestamp: new Date().toISOString(),
        details: "Intento de acceso a cuenta bloqueada",
      })
      return {
        success: false,
        message: "Cuenta bloqueada por demasiados intentos fallidos. Intente más tarde.",
      }
    }
    const user = this.users.find((u) => u.username === username && u.password === password)
    if (!user) {
      console.log("Usuario no encontrado o contraseña incorrecta")
      this.securityManager.registerFailedAttempt(username)
      return {
        success: false,
        message: "Usuario o contraseña incorrectos",
      }
    }
    console.log("Autenticación exitosa para:", username)
    this.currentUser = user
    user.recordSuccessfulLogin()
    this.saveUsers()
    const sessionData = this.securityManager.generateSessionToken(user.username, user.role)
    this.sessionToken = sessionData.token
    localStorage.setItem("sessionToken", this.sessionToken)
    localStorage.setItem("sessionExpires", sessionData.expires.toString())
    localStorage.setItem("currentUsername", user.username)
    localStorage.setItem("currentUserRole", user.role)
    this.securityManager.resetFailedAttempts(username)
    this.securityManager.startUserSession(user.username, user.role)
    this.securityManager.logSecurityEvent({
      type: "LOGIN_SUCCESS",
      username: username,
      timestamp: new Date().toISOString(),
      details: "Inicio de sesión exitoso",
    })
    if (this.currentUser.isPasswordExpired()) {
      this.securityManager.logSecurityEvent({
        type: "PASSWORD_EXPIRED",
        username: username,
        timestamp: new Date().toISOString(),
        details: "Contraseña expirada, se requiere cambio",
      })
      return { success: true, passwordExpired: true, message: "Su contraseña ha expirado. Debe cambiarla ahora." }
    }
    return { success: true }
  }

  logout() {
    if (this.currentUser) {
      this.securityManager.logUserActivity("LOGOUT", "Usuario cerró sesión")
      this.securityManager.endUserSession()
      this.securityManager.logSecurityEvent({
        type: "LOGOUT",
        username: this.currentUser.username,
        timestamp: new Date().toISOString(),
        details: "Cierre de sesión",
      })
    }
    this.currentUser = null
    this.sessionToken = null
    localStorage.removeItem("sessionToken")
    localStorage.removeItem("sessionExpires")
    localStorage.removeItem("currentUsername")
    localStorage.removeItem("currentUserRole")
  }

  validateSession() {
    const storedToken = localStorage.getItem("sessionToken")
    const storedUsername = localStorage.getItem("currentUsername")
    const storedRole = localStorage.getItem("currentUserRole")
    const sessionExpires = localStorage.getItem("sessionExpires")
    if (!storedToken || !storedUsername || !storedRole || !sessionExpires) {
      return false
    }
    if (Number.parseInt(sessionExpires) < Date.now()) {
      this.logout()
      return false
    }
    if (this.securityManager.validateSessionToken(storedToken, storedUsername, storedRole)) {
      const user = this.users.find((u) => u.username === storedUsername)
      if (user) {
        this.currentUser = user
        this.sessionToken = storedToken
        if (!this.securityManager.currentSessionLog) {
          this.securityManager.startUserSession(user.username, user.role)
        }
        return true
      }
    }
    return false
  }

  setPasswordExpiryPolicy(username, days) {
    const user = this.users.find((u) => u.username === username)
    if (user) {
      user.passwordExpiryDays = days
      this.saveUsers()
      this.securityManager.logSecurityEvent({
        type: "PASSWORD_POLICY_CHANGED",
        username: this.currentUser ? this.currentUser.username : "system",
        timestamp: new Date().toISOString(),
        details: `Política de expiración cambiada para ${username}: ${days} días`,
      })
      return { success: true, message: `Política actualizada: ${days} días` }
    }
    return { success: false, message: "Usuario no encontrado" }
  }

  hasPermission(action) {
    if (!this.currentUser) return false
    const permissions = {
      admin: ["all"],
      administrador: ["ingredients", "products", "inventory", "sales", "company", "users", "reports", "user_stats"],
      vendedor: ["sales", "inventory_view"],
    }
    if (action === "admin" && this.currentUser.role === "admin") {
      return true
    }
    const userPermissions = permissions[this.currentUser.role] || []
    return userPermissions.includes("all") || userPermissions.includes(action)
  }
}

class Ingredient {
  constructor(id, name, costPerKg) {
    this.id = id
    this.name = name
    this.costPerKg = costPerKg
  }
}

class Product {
  constructor(id, name, ingredients, photo, inventory) {
    this.id = id
    this.name = name
    this.ingredients = ingredients || []
    this.photo = photo
    this.inventory = inventory || 0
    this.productionCost = 0
    this.salePrice = 0
  }

  calculateProductionCost(ingredientsList, profitMargin) {
    this.productionCost = this.ingredients.reduce((total, ing) => {
      const ingredient = ingredientsList.find((i) => i.id === ing.ingredientId)
      return total + (ingredient ? ingredient.costPerKg * ing.quantity : 0)
    }, 0)
    this.salePrice = this.productionCost * (1 + profitMargin / 100)
    return this.productionCost
  }
}

class Sale {
  constructor(id, productId, productName, quantity, unitPrice, total, date, customerInfo, seller, invoiceNumber) {
    this.id = id
    this.productId = productId
    this.productName = productName
    this.quantity = quantity
    this.unitPrice = unitPrice
    this.total = total
    this.date = date || new Date()
    this.customerInfo = customerInfo || {
      name: "",
      document: "",
      address: "",
    }
    this.seller = seller || null
    this.invoiceNumber = invoiceNumber || null
  }
}

class Recipe {
  constructor(id, name, description, ingredients, steps, preparationTime, difficulty, image) {
    this.id = id
    this.name = name
    this.description = description || ""
    this.ingredients = ingredients || []
    this.steps = steps || []
    this.preparationTime = preparationTime || 0
    this.difficulty = difficulty || "Media"
    this.image = image || ""
    this.createdAt = new Date()
    this.updatedAt = new Date()
  }
}

class InvoiceNumberManager {
  constructor() {
    this.currentNumber = Number.parseInt(localStorage.getItem("lastInvoiceNumber")) || 0
    this.prefix = localStorage.getItem("invoicePrefix") || ""
  }

  generateNextNumber() {
    this.currentNumber += 1
    localStorage.setItem("lastInvoiceNumber", this.currentNumber.toString())
    const formattedNumber = this.currentNumber.toString().padStart(8, "0")
    return this.prefix + formattedNumber
  }

  setPrefix(prefix) {
    this.prefix = prefix
    localStorage.setItem("invoicePrefix", prefix)
  }

  getCurrentNumber() {
    return this.currentNumber
  }

  resetCounter(newNumber = 0) {
    this.currentNumber = newNumber
    localStorage.setItem("lastInvoiceNumber", this.currentNumber.toString())
  }
}

// Sistema Principal
class CharcuteriaSystem {
  constructor() {
    console.log("Inicializando sistema...")
    this.securityManager = new window.SecurityManager()
    this.company = new Company()
    this.userManager = new UserManager(this.securityManager)
    this.invoiceManager = new InvoiceNumberManager()
    this.ingredients = JSON.parse(localStorage.getItem("ingredients")) || []
    this.products = JSON.parse(localStorage.getItem("products")) || []
    this.sales = JSON.parse(localStorage.getItem("sales")) || []
    this.recipes = JSON.parse(localStorage.getItem("recipes")) || []
    this.profitMargin = Number.parseFloat(localStorage.getItem("profitMargin")) || 30
    this.taxRate = Number.parseFloat(localStorage.getItem("taxRate")) || 16
    this.initializeEventListeners()
    this.company.updateUI()
    this.checkExistingSession()
  }

  checkExistingSession() {
    console.log("Verificando sesión existente...")
    if (this.userManager.validateSession()) {
      console.log("Sesión válida encontrada, mostrando dashboard")
      this.showDashboard()
      this.securityManager.logSecurityEvent({
        type: "SESSION_RESUMED",
        username: this.userManager.currentUser.username,
        timestamp: new Date().toISOString(),
        details: "Sesión restaurada",
      })
    } else {
      console.log("No hay sesión válida, mostrando login")
      this.showLogin()
    }
  }

  initializeEventListeners() {
    console.log("Configurando event listeners...")
    const loginForm = document.getElementById("loginForm")
    if (loginForm) {
      loginForm.addEventListener("submit", (e) => {
        e.preventDefault()
        this.handleLogin()
      })
    }
    const togglePassword = document.getElementById("togglePassword")
    const passwordInput = document.getElementById("password")
    if (togglePassword && passwordInput) {
      togglePassword.addEventListener("click", () => {
        const type = passwordInput.getAttribute("type") === "password" ? "text" : "password"
        passwordInput.setAttribute("type", type)
        togglePassword.textContent = type === "password" ? "👁️" : "🙈"
      })
    }
    const logoutBtn = document.getElementById("logoutBtn")
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => {
        this.handleLogout()
      })
    }
    const modalClose = document.getElementById("modalClose")
    const modalContainer = document.getElementById("modalContainer")
    if (modalClose && modalContainer) {
      modalClose.addEventListener("click", () => {
        this.closeModal()
      })
      modalContainer.addEventListener("click", (e) => {
        if (e.target === modalContainer || e.target.classList.contains("modal-backdrop")) {
          this.closeModal()
        }
      })
    }
  }

  handleLogin() {
    console.log("Manejando login...")
    const username = this.securityManager.sanitizeInput(document.getElementById("username").value.trim())
    const password = document.getElementById("password").value
    const errorDiv = document.getElementById("loginError")
    if (errorDiv) {
      errorDiv.style.display = "none"
      errorDiv.textContent = ""
    }
    console.log("Intentando login con usuario:", username)
    const authResult = this.userManager.authenticate(username, password)
    if (authResult.success) {
      console.log("Login exitoso")
      if (authResult.passwordExpired) {
        alert("Su contraseña ha expirado. Debe cambiarla ahora.")
        this.showChangePasswordModal(username)
      } else {
        this.showDashboard()
      }
      document.getElementById("username").value = ""
      document.getElementById("password").value = ""
    } else {
      console.log("Login fallido:", authResult.message)
      if (errorDiv) {
        errorDiv.textContent = authResult.message || "Usuario o contraseña incorrectos"
        errorDiv.style.display = "block"
      } else {
        alert(authResult.message || "Usuario o contraseña incorrectos")
      }
    }
  }
      
  handleLogout() {
    this.userManager.logout()
    this.showLogin()
  }

  showLogin() {
    console.log("Mostrando pantalla de login")
    const loginScreen = document.getElementById("loginScreen")
    const dashboardScreen = document.getElementById("dashboardScreen")
    if (loginScreen) loginScreen.classList.add("active")
    if (dashboardScreen) dashboardScreen.classList.remove("active")
    this.company.updateLogos()
  }

  showDashboard() {
    console.log("Mostrando dashboard")
    const loginScreen = document.getElementById("loginScreen")
    const dashboardScreen = document.getElementById("dashboardScreen")
    const currentUserEl = document.getElementById("currentUser")
    if (loginScreen) loginScreen.classList.remove("active")
    if (dashboardScreen) dashboardScreen.classList.add("active")
    if (currentUserEl && this.userManager.currentUser) {
      currentUserEl.textContent = this.userManager.currentUser.username
    }
    this.setupNavigation()
    this.showDashboardContent()
    this.company.updateLogos()
  }

  setupNavigation() {
    const navMenu = document.getElementById("navMenu")
    if (!navMenu) return
    navMenu.innerHTML = ""
    const menuItems = [
      { text: "Dashboard", action: "dashboard", permission: "all" },
      { text: "Empresa", action: "company", permission: "company" },
      { text: "Usuarios", action: "users", permission: "users" },
      { text: "Estadísticas", action: "user_stats", permission: "user_stats" },
      { text: "Ingredientes", action: "ingredients", permission: "ingredients" },
      { text: "Productos", action: "products", permission: "products" },
      { text: "Inventario", action: "inventory", permission: "inventory" },
      { text: "Ventas", action: "sales", permission: "sales" },
      { text: "Recetas", action: "recipes", permission: "admin" },
      { text: "Reportes", action: "reports", permission: "reports" },
    ]
    menuItems.forEach((item) => {
      if (this.userManager.hasPermission(item.permission) || item.permission === "all") {
        const navItem = document.createElement("button")
        navItem.className = "nav-item"
        navItem.textContent = item.text
        navItem.setAttribute("data-section", item.action)
        navItem.addEventListener("click", () => {
          this.navigateTo(item.action)
        })
        navMenu.appendChild(navItem)
      }
    })
  }

  navigateTo(section) {
    console.log("Navegando a:", section)
    this.securityManager.logUserActivity("NAVIGATION", `Navegó a la sección: ${section}`, {
      section: section,
      timestamp: new Date().toISOString(),
    })
    document.querySelectorAll(".nav-item").forEach((item) => {
      item.classList.remove("active")
    })
    const activeItem = document.querySelector('[data-section="' + section + '"]')
    if (activeItem) {
      activeItem.classList.add("active")
    }
    switch (section) {
      case "dashboard":
        this.showDashboardContent()
        break
      case "company":
        this.showCompanySettings()
        break
      case "users":
        this.showUsers()
        break
      case "user_stats":
        this.showUserStatistics()
        break
      case "ingredients":
        this.showIngredients()
        break
      case "products":
        this.showProducts()
        break
      case "inventory":
        this.showInventory()
        break
      case "sales":
        this.showSales()
        break
      case "recipes":
        this.showRecipes()
        break
      case "reports":
        this.showReports()
        break
      default:
        this.showDashboardContent()
    }
  }

  // Continúa en la siguiente parte...
  saveData() {
    localStorage.setItem("ingredients", JSON.stringify(this.ingredients))
    localStorage.setItem("products", JSON.stringify(this.products))
    localStorage.setItem("sales", JSON.stringify(this.sales))
    localStorage.setItem("recipes", JSON.stringify(this.recipes))
  }

  showModal(title, content) {
    const modalContainer = document.getElementById("modalContainer")
    const modalTitle = document.getElementById("modalTitle")
    const modalBody = document.getElementById("modalBody")

    if (modalTitle) modalTitle.textContent = title
    if (modalBody) modalBody.innerHTML = content
    if (modalContainer) modalContainer.style.display = "flex"
  }

  closeModal() {
    const modalContainer = document.getElementById("modalContainer")
    if (modalContainer) modalContainer.style.display = "none"
  }

  // Métodos de visualización principales
  showDashboardContent() {
    const totalInventory = this.products.reduce((sum, p) => sum + (p.inventory || 0), 0)
    const formattedInventory = totalInventory.toLocaleString()
    const nextInvoiceNumber =
      this.invoiceManager.prefix + (this.invoiceManager.getCurrentNumber() + 1).toString().padStart(8, "0")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Dashboard - ${this.company.name}</h2>
        </div>
        <div class="card-body">
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-number">${this.ingredients.length}</div>
              <div class="stat-label">Ingredientes</div>
            </div>
            <div class="stat-card">
              <div class="stat-number">${this.products.length}</div>
              <div class="stat-label">Productos</div>
            </div>
            <div class="stat-card">
              <div class="stat-number">${formattedInventory}</div>
              <div class="stat-label">Inventario Total</div>
            </div>
            <div class="stat-card">
              <div class="stat-number">${this.sales.length}</div>
              <div class="stat-label">Ventas</div>
            </div>
          </div>
          <div style="margin-top: 2rem; padding: 1.5rem; background-color: var(--color-light); border-radius: 8px;">
            <h3>Bienvenido al Sistema</h3>
            <p>Usuario actual: <strong>${this.userManager.currentUser ? this.userManager.currentUser.username : ""}</strong></p>
            <p>Rol: <span class="badge badge-success">${this.userManager.currentUser ? this.userManager.currentUser.role : ""}</span></p>
            <p>Utilice el menú de navegación para acceder a las diferentes secciones del sistema.</p>
            <p><strong>Próximo número de factura:</strong> ${nextInvoiceNumber}</p>
          </div>
        </div>
      </div>
    `
    const contentArea = document.getElementById("contentArea")
    if (contentArea) {
      contentArea.innerHTML = content
    }
  }

  // Continúa con los demás métodos...
  showUserStatistics() {
    if (!this.userManager.hasPermission("user_stats")) {
      alert("No tiene permisos para acceder a esta sección")
      this.navigateTo("dashboard")
      return
    }

    const stats = this.securityManager.getUserStatistics()
    const userStats = this.securityManager.getUserStatistics(null, 7)

    const formatTime = (seconds) => {
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const secs = seconds % 60

      if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    // Obtener lista de usuarios únicos para el filtro
    const uniqueUsers = [...new Set(this.securityManager.userActivityLog.map((session) => session.username))]
    const userFilterOptions = uniqueUsers.map((username) => `<option value="${username}">${username}</option>`).join("")

    const activeUsersRows = Object.entries(stats.mostActiveUsers)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(
        ([username, sessions]) =>
          `<tr>
          <td>${username}</td>
          <td>${sessions}</td>
          <td><button class="btn btn-small btn-secondary" onclick="system.showUserDetailStats('${username}')">Ver Detalles</button></td>
        </tr>`,
      )
      .join("")

    const sectionsRows = Object.entries(stats.mostVisitedSections)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(
        ([section, visits]) =>
          `<tr>
          <td>${section}</td>
          <td>${visits}</td>
          <td>${((visits / stats.totalSessions) * 100).toFixed(1)}%</td>
        </tr>`,
      )
      .join("")

    const content = `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">📊 Estadísticas de Usuarios</h2>
      </div>
      <div class="card-body">
        <!-- Filtros de búsqueda -->
        <div style="margin-bottom: 2rem; padding: 1.5rem; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid #3498db;">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">🔍 Filtros de Búsqueda</h3>
          <div class="grid grid-3">
            <div class="form-group">
              <label for="userFilter">Filtrar por Usuario:</label>
              <select id="userFilter" class="form-control">
                <option value="">Todos los usuarios</option>
                ${userFilterOptions}
              </select>
            </div>
            <div class="form-group">
              <label for="daysFilter">Período (días):</label>
              <select id="daysFilter" class="form-control">
                <option value="7">Últimos 7 días</option>
                <option value="15">Últimos 15 días</option>
                <option value="30" selected>Últimos 30 días</option>
                <option value="60">Últimos 60 días</option>
                <option value="90">Últimos 90 días</option>
              </select>
            </div>
            <div class="form-group">
              <button id="applyFilters" class="btn btn-primary" style="margin-top: 1.5rem;">Aplicar Filtros</button>
              <button id="clearFilters" class="btn btn-secondary" style="margin-top: 1.5rem; margin-left: 0.5rem;">Limpiar</button>
            </div>
          </div>
        </div>

        <!-- Estadísticas generales -->
        <div id="generalStats" style="margin-bottom: 2rem;">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">📈 Resumen General (Últimos 30 días)</h3>
          <div class="stats-grid">
            <div class="stat-card" style="border-left: 4px solid #3498db;">
              <div class="stat-number" style="color: #3498db;">${stats.totalSessions}</div>
              <div class="stat-label">Total de Sesiones</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid #e74c3c;">
              <div class="stat-number" style="color: #e74c3c;">${formatTime(stats.averageSessionTime)}</div>
              <div class="stat-label">Tiempo Promedio por Sesión</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid #f39c12;">
              <div class="stat-number" style="color: #f39c12;">${stats.totalActions}</div>
              <div class="stat-label">Acciones Totales</div>
            </div>
            <div class="stat-card" style="border-left: 4px solid #27ae60;">
              <div class="stat-number" style="color: #27ae60;">${stats.averageActionsPerSession}</div>
              <div class="stat-label">Acciones por Sesión</div>
            </div>
          </div>
        </div>

        <!-- Actividad detallada del usuario filtrado -->
        <div id="userActivityDetails" style="display: none; margin-bottom: 2rem;">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">👤 Actividad Detallada del Usuario</h3>
          <div id="userActivityContent"></div>
        </div>

        <!-- Usuarios más activos -->
        <div id="activeUsersSection" style="margin-bottom: 2rem;">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">👥 Usuarios Más Activos</h3>
          ${
            activeUsersRows
              ? `
            <table class="table">
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>Sesiones</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                ${activeUsersRows}
              </tbody>
            </table>
          `
              : "<p>No hay datos de actividad disponibles.</p>"
          }
        </div>

        <!-- Secciones más visitadas -->
        <div id="sectionsSection" style="margin-bottom: 2rem;">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">📍 Secciones Más Visitadas</h3>
          ${
            sectionsRows
              ? `
            <table class="table">
              <thead>
                <tr>
                  <th>Sección</th>
                  <th>Visitas</th>
                  <th>% del Total</th>
                </tr>
              </thead>
              <tbody>
                ${sectionsRows}
              </tbody>
            </table>
          `
              : "<p>No hay datos de secciones visitadas.</p>"
          }
        </div>

        <!-- Actividad por día -->
        <div id="dailyActivitySection">
          <h3 style="color: #2c3e50; margin-bottom: 1rem;">📅 Actividad por Día (Últimos 7 días)</h3>
          ${
            Object.keys(userStats.sessionsByDay).length > 0
              ? `
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha</th>
                  <th>Sesiones</th>
                </tr>
              </thead>
              <tbody>
                ${Object.entries(userStats.sessionsByDay)
                  .sort(([a], [b]) => new Date(b) - new Date(a))
                  .map(
                    ([date, sessions]) =>
                      `<tr>
                        <td>${new Date(date).toLocaleDateString()}</td>
                        <td>${sessions}</td>
                      </tr>`,
                  )
                  .join("")}
              </tbody>
            </table>
          `
              : "<p>No hay datos de actividad por día.</p>"
          }
        </div>
      </div>
    </div>
  `

    document.getElementById("contentArea").innerHTML = content

    // Agregar event listeners para los filtros
    const applyFiltersBtn = document.getElementById("applyFilters")
    const clearFiltersBtn = document.getElementById("clearFilters")

    if (applyFiltersBtn) {
      applyFiltersBtn.addEventListener("click", () => {
        this.applyUserStatsFilters()
      })
    }

    if (clearFiltersBtn) {
      clearFiltersBtn.addEventListener("click", () => {
        this.clearUserStatsFilters()
      })
    }
  }

  applyUserStatsFilters() {
    const userFilter = document.getElementById("userFilter").value
    const daysFilter = Number.parseInt(document.getElementById("daysFilter").value)

    // Registrar actividad de filtrado
    this.securityManager.logUserActivity(
      "FILTER_USER_STATS",
      `Aplicó filtros: usuario=${userFilter || "todos"}, días=${daysFilter}`,
      {
        section: "user_stats",
        filterUser: userFilter,
        filterDays: daysFilter,
      },
    )

    if (userFilter) {
      // Mostrar actividad específica del usuario
      this.showFilteredUserActivity(userFilter, daysFilter)
    } else {
      // Actualizar estadísticas generales con el nuevo período
      this.updateGeneralStats(daysFilter)
    }
  }

  clearUserStatsFilters() {
    document.getElementById("userFilter").value = ""
    document.getElementById("daysFilter").value = "30"

    // Ocultar sección de actividad detallada
    const userActivityDetails = document.getElementById("userActivityDetails")
    if (userActivityDetails) {
      userActivityDetails.style.display = "none"
    }

    // Mostrar secciones generales
    const activeUsersSection = document.getElementById("activeUsersSection")
    const sectionsSection = document.getElementById("sectionsSection")
    const dailyActivitySection = document.getElementById("dailyActivitySection")

    if (activeUsersSection) activeUsersSection.style.display = "block"
    if (sectionsSection) sectionsSection.style.display = "block"
    if (dailyActivitySection) dailyActivitySection.style.display = "block"

    // Actualizar estadísticas generales
    this.updateGeneralStats(30)
  }

  showFilteredUserActivity(username, days) {
    const userStats = this.securityManager.getUserStatistics(username, days)
    const userSessions = this.securityManager.userActivityLog
      .filter((s) => s.username === username)
      .filter((s) => {
        const sessionDate = new Date(s.loginTime)
        const cutoffDate = new Date()
        cutoffDate.setDate(cutoffDate.getDate() - days)
        return sessionDate >= cutoffDate
      })
      .sort((a, b) => new Date(b.loginTime) - new Date(a.loginTime))
      .slice(0, 20) // Mostrar últimas 20 sesiones

    const formatTime = (seconds) => {
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const secs = seconds % 60

      if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    // Obtener actividades detalladas de las sesiones
    const allActivities = []
    userSessions.forEach((session) => {
      if (session.activities && session.activities.length > 0) {
        session.activities.forEach((activity) => {
          allActivities.push({
            ...activity,
            sessionId: session.sessionId,
            sessionStart: session.loginTime,
          })
        })
      }
    })

    // Ordenar actividades por timestamp
    allActivities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))

    const sessionsRows = userSessions
      .map(
        (session) =>
          `<tr>
      <td>${new Date(session.loginTime).toLocaleString()}</td>
      <td>${session.logoutTime ? new Date(session.logoutTime).toLocaleString() : "Activa"}</td>
      <td>${formatTime(session.totalTimeSpent || 0)}</td>
      <td>${session.actionsPerformed || 0}</td>
      <td>${session.sectionsVisited ? session.sectionsVisited.length : 0}</td>
      <td>
        <button class="btn btn-small btn-info" onclick="system.showSessionActivities('${session.sessionId}')">Ver Actividades</button>
      </td>
    </tr>`,
      )
      .join("")

    const activitiesRows = allActivities
      .slice(0, 50)
      .map(
        (activity) =>
          `<tr>
      <td>${new Date(activity.timestamp).toLocaleString()}</td>
      <td><span class="badge badge-info">${activity.action}</span></td>
      <td>${activity.section}</td>
      <td>${activity.description}</td>
    </tr>`,
      )
      .join("")

    const userActivityContent = `
    <div style="background-color: #f8f9fa; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem;">
      <h4 style="color: #2c3e50; margin-bottom: 1rem;">📊 Resumen de ${username} (Últimos ${days} días)</h4>
      <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
        <div class="stat-card">
          <div class="stat-number">${userStats.totalSessions}</div>
          <div class="stat-label">Sesiones Totales</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${formatTime(userStats.averageSessionTime)}</div>
          <div class="stat-label">Tiempo Promedio</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${userStats.totalActions}</div>
          <div class="stat-label">Acciones Totales</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${userStats.averageActionsPerSession}</div>
          <div class="stat-label">Acciones por Sesión</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">${formatTime(userStats.totalTimeSpent)}</div>
          <div class="stat-label">Tiempo Total</div>
        </div>
      </div>
    </div>

    <div style="margin-bottom: 2rem;">
      <h4 style="color: #2c3e50; margin-bottom: 1rem;">📋 Últimas 20 Sesiones</h4>
      <table class="table">
        <thead>
          <tr>
            <th>Inicio</th>
            <th>Fin</th>
            <th>Duración</th>
            <th>Acciones</th>
            <th>Secciones</th>
            <th>Detalles</th>
          </tr>
        </thead>
        <tbody>
          ${sessionsRows || '<tr><td colspan="6">No hay sesiones registradas</td></tr>'}
        </tbody>
      </table>
    </div>

    <div>
      <h4 style="color: #2c3e50; margin-bottom: 1rem;">🔍 Últimas 50 Actividades</h4>
      <table class="table">
        <thead>
          <tr>
            <th>Fecha/Hora</th>
            <th>Acción</th>
            <th>Sección</th>
            <th>Descripción</th>
          </tr>
        </thead>
        <tbody>
          ${activitiesRows || '<tr><td colspan="4">No hay actividades registradas</td></tr>'}
        </tbody>
      </table>
    </div>
  `

    // Mostrar la sección de actividad detallada
    const userActivityDetails = document.getElementById("userActivityDetails")
    const userActivityContentEl = document.getElementById("userActivityContent")

    if (userActivityDetails && userActivityContentEl) {
      userActivityContentEl.innerHTML = userActivityContent
      userActivityDetails.style.display = "block"
    }

    // Ocultar secciones generales cuando se filtra por usuario
    const activeUsersSection = document.getElementById("activeUsersSection")
    const sectionsSection = document.getElementById("sectionsSection")
    const dailyActivitySection = document.getElementById("dailyActivitySection")

    if (activeUsersSection) activeUsersSection.style.display = "none"
    if (sectionsSection) sectionsSection.style.display = "none"
    if (dailyActivitySection) dailyActivitySection.style.display = "none"

    // Actualizar estadísticas generales para el usuario específico
    this.updateGeneralStatsForUser(username, days)
  }

  updateGeneralStats(days) {
    const stats = this.securityManager.getUserStatistics(null, days)

    const formatTime = (seconds) => {
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const secs = seconds % 60

      if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    const generalStatsEl = document.getElementById("generalStats")
    if (generalStatsEl) {
      generalStatsEl.innerHTML = `
      <h3 style="color: #2c3e50; margin-bottom: 1rem;">📈 Resumen General (Últimos ${days} días)</h3>
      <div class="stats-grid">
        <div class="stat-card" style="border-left: 4px solid #3498db;">
          <div class="stat-number" style="color: #3498db;">${stats.totalSessions}</div>
          <div class="stat-label">Total de Sesiones</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #e74c3c;">
          <div class="stat-number" style="color: #e74c3c;">${formatTime(stats.averageSessionTime)}</div>
          <div class="stat-label">Tiempo Promedio por Sesión</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #f39c12;">
          <div class="stat-number" style="color: #f39c12;">${stats.totalActions}</div>
          <div class="stat-label">Acciones Totales</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #27ae60;">
          <div class="stat-number" style="color: #27ae60;">${stats.averageActionsPerSession}</div>
          <div class="stat-label">Acciones por Sesión</div>
        </div>
      </div>
    `
    }
  }

  updateGeneralStatsForUser(username, days) {
    const userStats = this.securityManager.getUserStatistics(username, days)

    const formatTime = (seconds) => {
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const secs = seconds % 60

      if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    const generalStatsEl = document.getElementById("generalStats")
    if (generalStatsEl) {
      generalStatsEl.innerHTML = `
      <h3 style="color: #2c3e50; margin-bottom: 1rem;">📈 Estadísticas de ${username} (Últimos ${days} días)</h3>
      <div class="stats-grid">
        <div class="stat-card" style="border-left: 4px solid #3498db;">
          <div class="stat-number" style="color: #3498db;">${userStats.totalSessions}</div>
          <div class="stat-label">Total de Sesiones</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #e74c3c;">
          <div class="stat-number" style="color: #e74c3c;">${formatTime(userStats.averageSessionTime)}</div>
          <div class="stat-label">Tiempo Promedio por Sesión</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #f39c12;">
          <div class="stat-number" style="color: #f39c12;">${userStats.totalActions}</div>
          <div class="stat-label">Acciones Totales</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid #27ae60;">
          <div class="stat-number" style="color: #27ae60;">${userStats.averageActionsPerSession}</div>
          <div class="stat-label">Acciones por Sesión</div>
        </div>
      </div>
    `
    }
  }

  showSessionActivities(sessionId) {
    const session = this.securityManager.userActivityLog.find((s) => s.sessionId === sessionId)
    if (!session) {
      alert("Sesión no encontrada")
      return
    }

    const formatTime = (seconds) => {
      const hours = Math.floor(seconds / 3600)
      const minutes = Math.floor((seconds % 3600) / 60)
      const secs = seconds % 60

      if (hours > 0) return `${hours}h ${minutes}m ${secs}s`
      if (minutes > 0) return `${minutes}m ${secs}s`
      return `${secs}s`
    }

    const activitiesRows = (session.activities || [])
      .map(
        (activity) =>
          `<tr>
      <td>${new Date(activity.timestamp).toLocaleTimeString()}</td>
      <td><span class="badge badge-info">${activity.action}</span></td>
      <td>${activity.section}</td>
      <td>${activity.description}</td>
      <td>${activity.details ? JSON.stringify(activity.details, null, 2) : "N/A"}</td>
    </tr>`,
      )
      .join("")

    this.showModal(
      `Actividades de Sesión - ${session.username}`,
      `<div style="max-width: 900px;">
      <div style="background-color: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <h4>Información de la Sesión</h4>
        <p><strong>Usuario:</strong> ${session.username}</p>
        <p><strong>Inicio:</strong> ${new Date(session.loginTime).toLocaleString()}</p>
        <p><strong>Fin:</strong> ${session.logoutTime ? new Date(session.logoutTime).toLocaleString() : "Sesión activa"}</p>
        <p><strong>Duración:</strong> ${formatTime(session.totalTimeSpent || 0)}</p>
        <p><strong>Acciones realizadas:</strong> ${session.actionsPerformed || 0}</p>
        <p><strong>Secciones visitadas:</strong> ${session.sectionsVisited ? session.sectionsVisited.join(", ") : "Ninguna"}</p>
      </div>
      
      <h4>Actividades Detalladas</h4>
      <div style="max-height: 400px; overflow-y: auto;">
        <table class="table">
          <thead>
            <tr>
              <th>Hora</th>
              <th>Acción</th>
              <th>Sección</th>
              <th>Descripción</th>
              <th>Detalles</th>
            </tr>
          </thead>
          <tbody>
            ${activitiesRows || '<tr><td colspan="5">No hay actividades registradas en esta sesión</td></tr>'}
        </tbody>
        </table>
      </div>
    </div>`,
    )
  }

  // Resto de métodos principales...
  showCompanySettings() {
    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Configuración de Empresa</h2>
        </div>
        <div class="card-body">
          <form id="companyForm" class="grid grid-2">
            <div class="form-group">
              <label for="companyNameInput">Nombre de la Empresa:</label>
              <input type="text" id="companyNameInput" value="${this.company.name}" required>
            </div>
            <div class="form-group">
              <label for="companyRifInput">RIF:</label>
              <input type="text" id="companyRifInput" value="${this.company.rif}" required>
            </div>
            <div class="form-group">
              <label for="companyLogoInput">Logo (URL):</label>
              <input type="url" id="companyLogoInput" value="${this.company.logo}">
            </div>
            <div class="form-group">
              <label for="companyAddressInput">Dirección:</label>
              <input type="text" id="companyAddressInput" value="${this.company.address}" required>
            </div>
            <div class="form-group">
              <label for="taxRateInput">Tasa de Impuesto/IVA (%):</label>
              <input type="number" id="taxRateInput" value="${this.taxRate}" min="0" max="100" step="0.1" required>
            </div>
            <div class="form-group">
              <label for="profitMarginInput">Margen de Ganancia (%):</label>
              <input type="number" id="profitMarginInput" value="${this.profitMargin}" min="0" step="0.1">
            </div>
            <div class="form-group">
              <label for="invoicePrefixInput">Prefijo de Factura:</label>
              <input type="text" id="invoicePrefixInput" value="${this.invoiceManager.prefix}" maxlength="4" placeholder="Ej: FAC-">
              <small class="form-text">Prefijo opcional para números de factura</small>
            </div>
            <div class="form-group">
              <label for="currentInvoiceNumber">Número Actual de Factura:</label>
              <input type="number" id="currentInvoiceNumber" value="${this.invoiceManager.getCurrentNumber()}" min="0">
              <small class="form-text">Cambiar solo si es necesario reiniciar la numeración</small>
            </div>
            <div class="form-group">
              <button type="submit" class="btn btn-primary">Guardar Cambios</button>
            </div>
          </form>
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    document.getElementById("companyForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const name = this.securityManager.sanitizeInput(document.getElementById("companyNameInput").value)
      const rif = this.securityManager.sanitizeInput(document.getElementById("companyRifInput").value)
      const logo = this.securityManager.sanitizeInput(document.getElementById("companyLogoInput").value)
      const address = this.securityManager.sanitizeInput(document.getElementById("companyAddressInput").value)
      const taxRate = Number.parseFloat(document.getElementById("taxRateInput").value)
      const margin = Number.parseFloat(document.getElementById("profitMarginInput").value)
      const invoicePrefix = this.securityManager.sanitizeInput(document.getElementById("invoicePrefixInput").value)
      const currentInvoiceNumber = Number.parseInt(document.getElementById("currentInvoiceNumber").value)

      this.company.updateInfo(name, rif, logo, address)
      this.taxRate = taxRate
      this.profitMargin = margin
      this.invoiceManager.setPrefix(invoicePrefix)
      if (currentInvoiceNumber !== this.invoiceManager.getCurrentNumber()) {
        this.invoiceManager.resetCounter(currentInvoiceNumber)
      }
      
      localStorage.setItem("taxRate", taxRate.toString())
      localStorage.setItem("profitMargin", margin.toString())

      this.securityManager.logUserActivity("COMPANY_CONFIG", "Configuración de empresa actualizada", {
        section: "company",
      })

      this.securityManager.logSecurityEvent({
        type: "COMPANY_UPDATED",
        username: this.userManager.currentUser.username,
        timestamp: new Date().toISOString(),
        details: "Configuración de empresa actualizada",
      })

      alert("Configuración guardada exitosamente")
    })
  }

  // Métodos adicionales que faltan...
  showUsers() {
    // Implementación completa de gestión de usuarios
    const usersRows = this.userManager.users
      .map((user) => {
        const isLocked = this.userManager.securityManager.isUserLocked(user.username)
        const statusBadge = isLocked
          ? '<span class="badge badge-danger">Bloqueada</span>'
          : '<span class="badge badge-success">Activa</span>'
        const unlockButton = isLocked
          ? `<button class="btn btn-small btn-warning unlock-user-btn" data-username="${user.username}">Desbloquear</button> `
          : ""
        const expiryDays = user.passwordExpiryDays || 90

        return `
          <tr>
            <td>${user.username}</td>
            <td>${user.role}</td>
            <td>${statusBadge}</td>
            <td>${user.lastLogin ? user.lastLogin.toLocaleString() : "Nunca"}</td>
            <td>${user.passwordLastChanged ? new Date(user.passwordLastChanged).toLocaleDateString() : "N/A"}</td>
            <td>${expiryDays} días</td>
            <td>
              ${unlockButton}
              <button class="btn btn-small btn-secondary change-password-btn" data-username="${user.username}">Cambiar Contraseña</button>
              <button class="btn btn-small btn-primary set-expiry-btn" data-username="${user.username}">Política</button>
              ${user.username !== "admin" ? `<button class="btn btn-small btn-danger delete-user-btn" data-username="${user.username}">Eliminar</button>` : ""}
            </td>
          </tr>
        `
      })
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Usuarios</h2>
          <button id="addUserBtn" class="btn btn-primary">Agregar Usuario</button>
        </div>
        <div class="card-body">
          <table class="table">
            <thead>
              <tr>
                <th>Usuario</th>
                <th>Rol</th>
                <th>Estado</th>
                <th>Último Login</th>
                <th>Último Cambio Clave</th>
                <th>Expiración</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              ${usersRows}
            </tbody>
          </table>
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    // Event listeners
    const addUserBtn = document.getElementById("addUserBtn")
    if (addUserBtn) {
      addUserBtn.addEventListener("click", () => {
        this.showAddUserModal()
      })
    }

    document.querySelectorAll(".change-password-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const username = e.target.getAttribute("data-username")
        this.showChangePasswordModal(username)
      })
    })

    document.querySelectorAll(".unlock-user-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const username = e.target.getAttribute("data-username")
        if (confirm(`¿Está seguro de desbloquear al usuario ${username}?`)) {
          const result = this.userManager.unlockUser(username)
          if (result.success) {
            alert(result.message)
            this.showUsers()
          } else {
            alert(result.message)
          }
        }
      })
    })

    document.querySelectorAll(".set-expiry-btn").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const username = e.target.getAttribute("data-username")
        this.showPasswordPolicyModal(username)
      })
    })
  }
    
  showPasswordPolicyModal(username) {
    const user = this.userManager.users.find((u) => u.username === username)
    if (!user) return
    const currentPolicy = user.passwordExpiryDays || 90

    this.showModal(
      "Política de Expiración de Contraseña",
      `<form id="passwordPolicyForm">
        <div class="form-group">
          <label for="expiryDays">Tiempo de vigencia de la contraseña:</label>
          <select id="expiryDays" class="form-control">
            <option value="30" ${currentPolicy === 30 ? "selected" : ""}>30 días</option>
            <option value="60" ${currentPolicy === 60 ? "selected" : ""}>60 días</option>
            <option value="90" ${currentPolicy === 90 ? "selected" : ""}>90 días</option>
            <option value="120" ${currentPolicy === 120 ? "selected" : ""}>120 días</option>
          </select>
        </div>
        <input type="hidden" id="policyUsername" value="${username}">
        <button type="submit" class="btn btn-primary">Guardar Política</button>
      </form>`,
    )

    document.getElementById("passwordPolicyForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const username = document.getElementById("policyUsername").value
      const days = Number.parseInt(document.getElementById("expiryDays").value)
      const result = this.userManager.setPasswordExpiryPolicy(username, days)
      if (result.success) {
        alert(result.message)
        this.closeModal()
        this.showUsers()
      } else {
        alert(result.message)
      }
    })
  }

  showChangePasswordModal(username) {
    this.showModal(
      "Cambiar Contraseña",
      `<form id="changePasswordForm">
        <div class="form-group">
          <label for="newPassword">Nueva Contraseña:</label>
          <input type="password" id="newPassword" maxlength="12" required>
          <div class="password-requirements" style="margin-top: 10px; font-size: 0.8rem;">
            <p style="margin: 0;">La contraseña debe tener:</p>
            <ul style="margin-top: 5px; padding-left: 20px;">
              <li id="req-length" style="color: #999;">Máximo 12 caracteres</li>
              <li id="req-uppercase" style="color: #999;">Al menos una mayúscula</li>
              <li id="req-lowercase" style="color: #999;">Al menos una minúscula</li>
              <li id="req-number" style="color: #999;">Al menos un número</li>
              <li id="req-special" style="color: #999;">Al menos un carácter especial</li>
            </ul>
          </div>
        </div>
        <div class="form-group">
          <label for="confirmPassword">Confirmar Nueva Contraseña:</label>
          <input type="password" id="confirmPassword" maxlength="12" required>
        </div>
        <input type="hidden" id="usernameInput" value="${username}">
        <button type="submit" class="btn btn-primary">Cambiar Contraseña</button>
      </form>`,
    )

    const newPasswordInput = document.getElementById("newPassword")
    if (newPasswordInput) {
      newPasswordInput.addEventListener("input", function () {
        const password = this.value
        const hasUpperCase = /[A-Z]/.test(password)
        const hasLowerCase = /[a-z]/.test(password)
        const hasNumbers = /[0-9]/.test(password)
        const hasSpecialChars = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
        const isValidLength = password.length <= 12 && password.length > 0
        
        document.getElementById("req-uppercase").style.color = hasUpperCase ? "#2ecc71" : "#999"
        document.getElementById("req-lowercase").style.color = hasLowerCase ? "#2ecc71" : "#999"
        document.getElementById("req-number").style.color = hasNumbers ? "#2ecc71" : "#999"
        document.getElementById("req-special").style.color = hasSpecialChars ? "#2ecc71" : "#999"
        document.getElementById("req-length").style.color = isValidLength ? "#2ecc71" : "#999"
      })
    }

    document.getElementById("changePasswordForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const username = document.getElementById("usernameInput").value
      
      const newPassword = document.getElementById("newPassword").value
      const confirmPassword = document.getElementById("confirmPassword").value

      if (newPassword !== confirmPassword) {
        alert("Las contraseñas no coinciden")
        return
      }

      const result = this.userManager.changePassword(username, newPassword)
      if (result.success) {
        alert(result.message)
        this.closeModal()
      } else {
        if (result.validation) {
          let errorMsg = result.message + ":\n"
          if (!result.validation.hasUpperCase) errorMsg += "- Falta una letra mayúscula\n"
          if (!result.validation.hasLowerCase) errorMsg += "- Falta una letra minúscula\n"
          if (!result.validation.hasNumbers) errorMsg += "- Falta un número\n"
          if (!result.validation.hasSpecialChars) errorMsg += "- Falta un carácter especial\n"
          alert(errorMsg)
        } else {
          alert(result.message)
        }
      }
    })
  }

  showAddUserModal() {
    this.showModal(
      "Agregar Usuario",
      `<form id="addUserForm">
        <div class="form-group">
          <label for="newUsername">Nombre de Usuario:</label>
          <input type="text" id="newUsername" required>
        </div>
        <div class="form-group">
          <label for="newPassword">Contraseña:</label>
          <input type="password" id="newPassword" required>
          <small class="form-text">La contraseña debe tener al menos 6 caracteres</small>
        </div>
        <div class="form-group">
          <label for="newUserRole">Rol:</label>
          <select id="newUserRole" required>
            <option value="">Seleccionar rol</option>
            <option value="admin">Admin</option>
            <option value="administrador">Administrador</option>
            <option value="vendedor">Vendedor</option>
          </select>
        </div>
        <button type="submit" class="btn btn-primary">Agregar Usuario</button>
      </form>`,
    )

    document.getElementById("addUserForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const username = this.securityManager.sanitizeInput(document.getElementById("newUsername").value)
      const password = document.getElementById("newPassword").value
      const role = document.getElementById("newUserRole").value

      if (password.length < 6) {
        alert("La contraseña debe tener al menos 6 caracteres")
        return
      }

      const result = this.userManager.addUser(username, password, role)
      if (result.success) {
        this.securityManager.logUserActivity("USER_CREATED", `Usuario creado: ${username}`, {
          section: "users",
          newUserRole: role,
        })
        this.securityManager.logSecurityEvent({
          type: "USER_ADDED",
          username: this.userManager.currentUser.username,
          timestamp: new Date().toISOString(),
          details: "Usuario agregado: " + username,
        })
        alert(result.message)
        this.closeModal()
        this.showUsers()
      } else {
        alert(result.message)
      }
    })
  }

  // Métodos para ingredientes, productos, inventario, ventas, recetas y reportes
  showIngredients() {
    this.securityManager.logUserActivity("VIEW_INGREDIENTS", "Visualizó la lista de ingredientes", {
      section: "ingredients",
    })

    const ingredientsRows = this.ingredients
      .map(
        (ing) => `
        <tr>
          <td>${ing.id}</td>
          <td>${ing.name}</td>
          <td>$${ing.costPerKg.toFixed(2)}</td>
          <td>
            <button class="btn btn-small btn-danger" onclick="system.deleteIngredient(${ing.id})">Eliminar</button>
          </td>
        </tr>
      `,
      )
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Ingredientes</h2>
          <button id="addIngredientBtn" class="btn btn-primary">Agregar Ingrediente</button>
        </div>
        <div class="card-body">
          ${
            this.ingredients.length === 0
              ? "<p>No hay ingredientes registrados. Agregue el primer ingrediente.</p>"
              : `<table class="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Nombre</th>
                    <th>Costo por Kg</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  ${ingredientsRows}
                </tbody>
              </table>`
          }
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    const addBtn = document.getElementById("addIngredientBtn")
    if (addBtn) {
      addBtn.addEventListener("click", () => {
        this.showAddIngredientModal()
      })
    }
  }

  showAddIngredientModal() {
    this.showModal(
      "Agregar Ingrediente",
      `<form id="addIngredientForm">
        <div class="form-group">
          <label for="ingredientName">Nombre del Ingrediente:</label>
          <input type="text" id="ingredientName" required>
        </div>
        <div class="form-group">
          <label for="ingredientCost">Costo por Kg:</label>
          <input type="number" id="ingredientCost" min="0" step="0.01" required>
        </div>
        <button type="submit" class="btn btn-primary">Agregar Ingrediente</button>
      </form>`,
    )

    document.getElementById("addIngredientForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const name = this.securityManager.sanitizeInput(document.getElementById("ingredientName").value)
      const cost = Number.parseFloat(document.getElementById("ingredientCost").value)

      const newIngredient = new Ingredient(Date.now(), name, cost)
      this.ingredients.push(newIngredient)
      this.saveData()

      this.securityManager.logUserActivity("INGREDIENT_CREATED", `Ingrediente creado: ${name}`, {
        section: "ingredients",
        cost: cost,
      })

      alert("Ingrediente agregado exitosamente")
      this.closeModal()
      this.showIngredients()
    })
  }

  deleteIngredient(id) {
    if (confirm("¿Está seguro de eliminar este ingrediente?")) {
      const ingredient = this.ingredients.find((i) => i.id === id)
      this.ingredients = this.ingredients.filter((i) => i.id !== id)
      this.saveData()

      this.securityManager.logUserActivity(
        "INGREDIENT_DELETED",
        `Ingrediente eliminado: ${ingredient ? ingredient.name : id}`,
        {
          section: "ingredients",
        },
      )

      alert("Ingrediente eliminado exitosamente")
      this.showIngredients()
    }
  }

  showProducts() {
    this.securityManager.logUserActivity("VIEW_PRODUCTS", "Visualizó la lista de productos", {
      section: "products",
    })

    const productsRows = this.products
      .map(
        (product) => `
        <tr>
          <td>
            <img src="${product.photo || "/placeholder.svg?height=50&width=50"}" 
                 class="product-image" alt="${product.name}" 
                 onerror="this.src='/placeholder.svg?height=50&width=50'">
          </td>
          <td>${product.name}</td>
          <td>$${(product.productionCost || 0).toFixed(2)}</td>
          <td>$${(product.salePrice || 0).toFixed(2)}</td>
          <td>${typeof product.inventory === "number" ? product.inventory.toFixed(3) : product.inventory || 0}</td>
          <td>
            <button class="btn btn-small btn-secondary" onclick="system.editProduct(${product.id})">Editar</button>
            <button class="btn btn-small btn-danger" onclick="system.deleteProduct(${product.id})">Eliminar</button>
          </td>
        </tr>
      `,
      )
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Productos</h2>
          <button id="addProductBtn" class="btn btn-primary">Agregar Producto</button>
        </div>
        <div class="card-body">
          ${
            this.products.length === 0
              ? "<p>No hay productos registrados. Agregue el primer producto.</p>"
              : `<table class="table">
                <thead>
                  <tr>
                    <th>Foto</th>
                    <th>Nombre</th>
                    <th>Costo Producción</th>
                    <th>Precio Venta</th>
                    <th>Inventario</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  ${productsRows}
                </tbody>
              </table>`
          }
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    const addProductBtn = document.getElementById("addProductBtn")
    if (addProductBtn) {
      addProductBtn.addEventListener("click", () => {
        this.showAddProductModal()
      })
    }
  }

  showAddProductModal() {
    if (this.ingredients.length === 0) {
      alert("Debe agregar ingredientes antes de crear productos")
      return
    }

    const ingredientOptions = this.ingredients
      .map((ing) => `<option value="${ing.id}">${ing.name} ($${ing.costPerKg.toFixed(2)}/kg)</option>`)
      .join("")

    this.showModal(
      "Agregar Producto",
      `<form id="addProductForm">
        <div class="form-group">
          <label for="productName">Nombre del Producto:</label>
          <input type="text" id="productName" required>
        </div>
        <div class="form-group">
          <label for="productPhoto">Foto (URL):</label>
          <input type="url" id="productPhoto">
        </div>
        <div class="form-group">
          <label for="productInventory">Inventario Inicial:</label>
          <input type="number" id="productInventory" min="0" value="0" required>
        </div>
        <div class="form-group">
          <h4>Ingredientes del Producto:</h4>
          <div id="ingredientsList">
            <div class="ingredient-row">
              <select class="ingredient-select" required>
                <option value="">Seleccionar ingrediente</option>
                ${ingredientOptions}
              </select>
              <input type="number" class="ingredient-quantity" placeholder="Cantidad (kg)" step="0.01" min="0.01" required>
              <button type="button" class="btn btn-small btn-danger remove-ingredient">Eliminar</button>
            </div>
          </div>
          <button type="button" id="addIngredientRow" class="btn btn-small btn-secondary">Agregar Ingrediente</button>
        </div>
        <div class="form-group">
          <div id="costCalculation" style="background-color: var(--color-light); padding: 1rem; border-radius: 5px; margin-top: 1rem;">
            <h4>Cálculo de Costos:</h4>
            <p>Costo de Producción: $<span id="productionCost">0.00</span></p>
            <p>Margen de Ganancia: ${this.profitMargin}%</p>
            <p><strong>Precio de Venta: $<span id="salePrice">0.00</span></strong></p>
          </div>
        </div>
        <button type="submit" class="btn btn-primary">Agregar Producto</button>
      </form>`,
    )

    this.setupProductModalListeners()
  }

  setupProductModalListeners() {
    const addIngredientBtn = document.getElementById("addIngredientRow")
    const ingredientsList = document.getElementById("ingredientsList")

    if (addIngredientBtn) {
      addIngredientBtn.addEventListener("click", () => {
        const ingredientOptions = this.ingredients
          .map((ing) => `<option value="${ing.id}">${ing.name} ($${ing.costPerKg.toFixed(2)}/kg)</option>`)
          .join("")

        const newRow = document.createElement("div")
        newRow.className = "ingredient-row"
        newRow.innerHTML = `
          <select class="ingredient-select" required>
            <option value="">Seleccionar ingrediente</option>
            ${ingredientOptions}
          </select>
          <input type="number" class="ingredient-quantity" placeholder="Cantidad (kg)" step="0.01" min="0.01" required>
          <button type="button" class="btn btn-small btn-danger remove-ingredient">Eliminar</button>
        `

        ingredientsList.appendChild(newRow)
        this.updateIngredientListeners()
      })
    }

    this.updateIngredientListeners()

    const form = document.getElementById("addProductForm")
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault()
        this.handleAddProduct()
      })
    }
  }

  updateIngredientListeners() {
    document.querySelectorAll(".remove-ingredient").forEach((btn) => {
      btn.removeEventListener("click", this.removeIngredientRow)
      btn.addEventListener("click", this.removeIngredientRow)
    })

    document.querySelectorAll(".ingredient-select, .ingredient-quantity").forEach((input) => {
      input.removeEventListener("change", this.calculateProductCosts.bind(this))
      input.removeEventListener("input", this.calculateProductCosts.bind(this))
      input.addEventListener("change", this.calculateProductCosts.bind(this))
      input.addEventListener("input", this.calculateProductCosts.bind(this))
    })
  }

  removeIngredientRow(e) {
    const row = e.target.closest(".ingredient-row")
    if (row && document.querySelectorAll(".ingredient-row").length > 1) {
      row.remove()
      if (window.system) {
        window.system.calculateProductCosts()
      }
    }
  }

  calculateProductCosts() {
    const rows = document.querySelectorAll(".ingredient-row")
    let totalCost = 0

    rows.forEach((row) => {
      const select = row.querySelector(".ingredient-select")
      const quantityInput = row.querySelector(".ingredient-quantity")

      if (select.value && quantityInput.value) {
        const ingredientId = Number.parseInt(select.value)
        const quantity = Number.parseFloat(quantityInput.value)
        const ingredient = this.ingredients.find((ing) => ing.id === ingredientId)

        if (ingredient) {
          totalCost += ingredient.costPerKg * quantity
        }
      }
    })

    const salePrice = totalCost * (1 + this.profitMargin / 100)

    const productionCostEl = document.getElementById("productionCost")
    const salePriceEl = document.getElementById("salePrice")

    if (productionCostEl) productionCostEl.textContent = totalCost.toFixed(2)
    if (salePriceEl) salePriceEl.textContent = salePrice.toFixed(2)
  }

  handleAddProduct() {
    const name = this.securityManager.sanitizeInput(document.getElementById("productName").value)
    const photo = this.securityManager.sanitizeInput(document.getElementById("productPhoto").value)
    const inventory = Number.parseInt(document.getElementById("productInventory").value)

    const ingredients = []
    const rows = document.querySelectorAll(".ingredient-row")

    rows.forEach((row) => {
      const select = row.querySelector(".ingredient-select")
      const quantityInput = row.querySelector(".ingredient-quantity")

      if (select.value && quantityInput.value) {
        ingredients.push({
          ingredientId: Number.parseInt(select.value),
          quantity: Number.parseFloat(quantityInput.value),
        })
      }
    })

    if (ingredients.length === 0) {
      alert("Debe agregar al menos un ingrediente al producto")
      return
    }

    const newProduct = new Product(Date.now(), name, ingredients, photo, inventory)
    newProduct.calculateProductionCost(this.ingredients, this.profitMargin)
    this.products.push(newProduct)
    this.saveData()

    this.securityManager.logUserActivity("PRODUCT_CREATED", `Producto creado: ${name}`, {
      section: "products",
      productionCost: newProduct.productionCost,
      salePrice: newProduct.salePrice,
    })

    alert("Producto agregado exitosamente")
    this.closeModal()
    this.showProducts()
  }

  editProduct(id) {
    // Implementación para editar producto
    alert("Función de edición en desarrollo")
  }

  deleteProduct(id) {
    if (confirm("¿Está seguro de eliminar este producto?")) {
      const product = this.products.find((p) => p.id === id)
      this.products = this.products.filter((p) => p.id !== id)
      this.saveData()

      this.securityManager.logUserActivity("PRODUCT_DELETED", `Producto eliminado: ${product ? product.name : id}`, {
        section: "products",
      })

      alert("Producto eliminado exitosamente")
      this.showProducts()
    }
  }

  showInventory() {
    this.securityManager.logUserActivity("VIEW_INVENTORY", "Visualizó el inventario", {
      section: "inventory",
    })

    const inventoryRows = this.products
      .map((product) => {
        const inventory = product.inventory || 0
        let statusClass = "success"
        let statusText = "En Stock"

        if (inventory === 0) {
          statusClass = "danger"
          statusText = "Sin Stock"
        } else if (inventory <= 10) {
          statusClass = "warning"
          statusText = "Bajo Stock"
        }

        return `
          <tr>
            <td>${product.name}</td>
            <td>${typeof inventory === "number" ? inventory.toFixed(3) : inventory}</td>
            <td><span class="badge badge-${statusClass}">${statusText}</span></td>
          </tr>
        `
      })
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Inventario</h2>
        </div>
        <div class="card-body">
          ${
            this.products.length === 0
              ? "<p>No hay productos en inventario.</p>"
              : `<table class="table">
                <thead>
                  <tr>
                    <th>Producto</th>
                    <th>Cantidad en Stock</th>
                    <th>Estado</th>
                  </tr>
                </thead>
                <tbody>
                  ${inventoryRows}
                </tbody>
              </table>`
          }
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content
  }

  showSales() {
    this.securityManager.logUserActivity("VIEW_SALES", "Visualizó las ventas", {
      section: "sales",
    })

    const isAdmin =
      this.userManager.currentUser.role === "admin" || this.userManager.currentUser.role === "administrador"
    const currentUsername = this.userManager.currentUser.username

    let filteredSales = this.sales
    if (!isAdmin) {
      filteredSales = this.sales.filter((sale) => sale.seller === currentUsername)
    }

    const totalSales = filteredSales.reduce((sum, sale) => sum + (sale.total || 0), 0)

    const salesRows = filteredSales
      .map(
        (sale) => `
        <tr>
          <td>${sale.invoiceNumber || sale.id}</td>
          <td>${sale.productName || "N/A"}</td>
          <td>${sale.customerInfo?.name || "N/A"}</td>
          <td>${sale.customerInfo?.document || "N/A"}</td>
          <td>${typeof sale.quantity === "number" ? sale.quantity.toFixed(3) : sale.quantity}</td>
          <td>$${(sale.unitPrice || 0).toFixed(2)}</td>
          <td>$${(sale.total || 0).toFixed(2)}</td>
          <td>${new Date(sale.date).toLocaleDateString()}</td>
          <td>${sale.seller || "N/A"}</td>
          <td>
            <button class="btn btn-small btn-secondary" onclick="system.printInvoice(${JSON.stringify(sale).replace(/"/g, "&quot;")})">Reimprimir</button>
          </td>
        </tr>
      `,
      )
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Ventas</h2>
          <button id="addSaleBtn" class="btn btn-primary">Nueva Venta</button>
        </div>
        <div class="card-body">
          <div class="stats-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom: 1.5rem;">
            <div class="stat-card">
              <div class="stat-number">${filteredSales.length}</div>
              <div class="stat-label">${isAdmin ? "Total de Ventas" : "Mis Ventas"}</div>
            </div>
            <div class="stat-card">
              <div class="stat-number">$${totalSales.toFixed(2)}</div>
              <div class="stat-label">Ingresos ${isAdmin ? "Totales" : "Generados"}</div>
            </div>
          </div>
          ${
            filteredSales.length === 0
              ? `<p>No hay ventas ${isAdmin ? "registradas" : "realizadas por usted"}.</p>`
              : `<table class="table">
                <thead>
                  <tr>
                    <th>Factura #</th>
                    <th>Producto</th>
                    <th>Cliente</th>
                    <th>Documento</th>
                    <th>Cantidad</th>
                    <th>Precio Unit.</th>
                    <th>Total</th>
                    <th>Fecha</th>
                    <th>Vendedor</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  ${salesRows}
                </tbody>
              </table>`
          }
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    const addSaleBtn = document.getElementById("addSaleBtn")
    if (addSaleBtn) {
      addSaleBtn.addEventListener("click", () => {
        this.showAddSaleModal()
      })
    }
  }

  showAddSaleModal() {
    if (this.products.length === 0) {
      alert("No hay productos disponibles para vender. Agregue productos primero.")
      return
    }

    const availableProducts = this.products.filter((p) => p.inventory > 0)
    if (availableProducts.length === 0) {
      alert("No hay productos con inventario disponible para vender.")
      return
    }

    const productOptions = availableProducts
      .map(
        (product) => `
        <option value="${product.id}" data-price="${product.salePrice}" data-inventory="${product.inventory}">
          ${product.name} ($${product.salePrice.toFixed(2)}) - ${product.inventory} disponibles
        </option>
      `,
      )
      .join("")

    this.showModal(
      "Nueva Venta",
      `<form id="addSaleForm">
        <div class="form-group">
          <label for="saleProduct">Producto:</label>
          <select id="saleProduct" required>
            <option value="">Seleccionar producto</option>
            ${productOptions}
          </select>
        </div>
        <div class="form-group">
          <label for="saleQuantity">Cantidad:</label>
          <input type="number" id="saleQuantity" min="0.001" step="0.001" value="1" required>
          <small id="inventoryWarning" class="form-text" style="color: var(--color-danger);"></small>
        </div>
        <div class="form-group">
          <h4>Información del Cliente:</h4>
          <label for="customerName">Nombre del Cliente:</label>
          <input type="text" id="customerName" required>
        </div>
        <div class="form-group">
          <label for="customerDocument">Cédula o RIF:</label>
          <input type="text" id="customerDocument" required>
        </div>
        <div class="form-group">
          <label for="customerAddress">Dirección:</label>
          <input type="text" id="customerAddress" required>
        </div>
        <div id="saleCalculation" style="background-color: var(--color-light); padding: 1rem; border-radius: 5px; margin-top: 1rem;">
          <h4>Detalle de Venta:</h4>
          <p>Precio Unitario: $<span id="unitPrice">0.00</span></p>
          <p>Subtotal: $<span id="subtotal">0.00</span></p>
          <p>IVA (${this.taxRate}%): $<span id="tax">0.00</span></p>
          <p><strong>Total: $<span id="total">0.00</span></strong></p>
          <p><strong>Número de Factura: <span id="invoicePreview">${this.invoiceManager.prefix}${(this.invoiceManager.getCurrentNumber() + 1).toString().padStart(8, "0")}</span></strong></p>
        </div>
        <button type="submit" class="btn btn-primary" style="margin-top: 1rem;">Registrar Venta</button>
      </form>`,
    )

    const productSelect = document.getElementById("saleProduct")
    const quantityInput = document.getElementById("saleQuantity")

    productSelect.addEventListener("change", () => this.updateSaleCalculations())
    quantityInput.addEventListener("input", () => this.updateSaleCalculations())

    document.getElementById("addSaleForm").addEventListener("submit", (e) => {
      e.preventDefault()
      this.handleAddSale()
    })

    this.updateSaleCalculations()
  }

  updateSaleCalculations() {
    const productSelect = document.getElementById("saleProduct")
    const quantityInput = document.getElementById("saleQuantity")
    const unitPriceEl = document.getElementById("unitPrice")
    const subtotalEl = document.getElementById("subtotal")
    const taxEl = document.getElementById("tax")
    const totalEl = document.getElementById("total")
    const inventoryWarning = document.getElementById("inventoryWarning")

    if (inventoryWarning) inventoryWarning.textContent = ""

    if (!productSelect || !productSelect.value) {
      if (unitPriceEl) unitPriceEl.textContent = "0.00"
      if (subtotalEl) subtotalEl.textContent = "0.00"
      if (taxEl) taxEl.textContent = "0.00"
      if (totalEl) totalEl.textContent = "0.00"
      return
    }

    const selectedOption = productSelect.options[productSelect.selectedIndex]
    const unitPrice = Number.parseFloat(selectedOption.getAttribute("data-price") || "0")
    const availableInventory = Number.parseFloat(selectedOption.getAttribute("data-inventory") || "0")
    let quantity = Number.parseFloat(quantityInput.value || "1")

    if (quantity < 0.001) {
      quantity = 0.001
      quantityInput.value = 0.001
    }

    if (quantity > availableInventory) {
      if (inventoryWarning) {
        inventoryWarning.textContent = "¡Cantidad excede el inventario disponible!"
      }
      quantity = availableInventory
      quantityInput.value = availableInventory
    }

    const subtotal = unitPrice * quantity
    const tax = subtotal * (this.taxRate / 100)
    const total = subtotal + tax

    if (unitPriceEl) unitPriceEl.textContent = unitPrice.toFixed(2)
    if (subtotalEl) subtotalEl.textContent = subtotal.toFixed(2)
    if (taxEl) taxEl.textContent = tax.toFixed(2)
    if (totalEl) totalEl.textContent = total.toFixed(2)
  }

  handleAddSale() {
    const productSelect = document.getElementById("saleProduct")
    const quantityInput = document.getElementById("saleQuantity")
    const customerNameInput = document.getElementById("customerName")
    const customerDocumentInput = document.getElementById("customerDocument")
    const customerAddressInput = document.getElementById("customerAddress")

    if (
      !productSelect.value ||
      !quantityInput.value ||
      !customerNameInput.value ||
      !customerDocumentInput.value ||
      !customerAddressInput.value
    ) {
      alert("Por favor complete todos los campos requeridos")
      return
    }

    const productId = Number.parseInt(productSelect.value)
    const quantity = Number.parseFloat(quantityInput.value)
    const customerInfo = {
      name: this.securityManager.sanitizeInput(customerNameInput.value),
      document: this.securityManager.sanitizeInput(customerDocumentInput.value),
      address: this.securityManager.sanitizeInput(customerAddressInput.value),
    }

    const product = this.products.find((p) => p.id === productId)
    if (!product) {
      alert("Producto no encontrado")
      return
    }

    if (quantity > product.inventory) {
      alert("No hay suficiente inventario disponible")
      return
    }

    const unitPrice = product.salePrice
    const subtotal = unitPrice * quantity
    const tax = subtotal * (this.taxRate / 100)
    const total = subtotal + tax
    const invoiceNumber = this.invoiceManager.generateNextNumber()

    const newSale = new Sale(
      Date.now(),
      productId,
      product.name,
      quantity,
      unitPrice,
      total,
      new Date(),
      customerInfo,
      this.userManager.currentUser.username,
      invoiceNumber,
    )

    product.inventory -= quantity
    this.sales.push(newSale)
    this.saveData()

    this.securityManager.logUserActivity("SALE_CREATED", `Venta registrada: ${product.name} x ${quantity}`, {
      section: "sales",
      invoiceNumber: invoiceNumber,
      total: total,
      customer: customerInfo.name,
    })

    this.closeModal()

    if (confirm("Venta registrada exitosamente. ¿Desea imprimir la factura?")) {
      this.printInvoice(newSale)
    }

    this.showSales()
  }

  printInvoice(sale) {
    const company = this.company
    const saleDate = new Date(sale.date)
    const subtotal = sale.total / (1 + this.taxRate / 100)
    const tax = sale.total - subtotal

    const invoiceContent = `
<!DOCTYPE html>
<html>
<head>
  <title>Factura #${sale.invoiceNumber || sale.id}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 20px; }
    .logo { width: 120px; height: auto; margin-bottom: 10px; }
    .company-info { margin-bottom: 20px; }
    .customer-info { margin-bottom: 20px; }
    .sale-details { margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .totals { text-align: right; }
    .total-row { font-weight: bold; }
    @media print { 
      body { margin: 0; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="header">
    ${company.logo ? `<img src="${company.logo}" alt="${company.name} Logo" class="logo" onerror="this.style.display='none'">` : ""}
    <h1>${company.name}</h1>
    <p>RIF: ${company.rif}</p>
    <p>${company.address}</p>
  </div>
  
  <div class="sale-details">
    <h2>FACTURA #${sale.invoiceNumber || sale.id}</h2>
    <p><strong>Fecha:</strong> ${saleDate.toLocaleDateString()} ${saleDate.toLocaleTimeString()}</p>
    <p><strong>Vendedor:</strong> ${sale.seller}</p>
  </div>
  
  <div class="customer-info">
    <h3>Información del Cliente:</h3>
    <p><strong>Nombre:</strong> ${sale.customerInfo.name}</p>
    <p><strong>Documento:</strong> ${sale.customerInfo.document}</p>
    <p><strong>Dirección:</strong> ${sale.customerInfo.address}</p>
  </div>
  
  <table>
    <thead>
      <tr>
        <th>Producto</th>
        <th>Cantidad</th>
        <th>Precio Unitario</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>${sale.productName}</td>
        <td>${typeof sale.quantity === "number" ? sale.quantity.toFixed(3) : sale.quantity}</td>
        <td>$${sale.unitPrice.toFixed(2)}</td>
        <td>$${(sale.unitPrice * sale.quantity).toFixed(2)}</td>
      </tr>
    </tbody>
  </table>
  
  <div class="totals">
    <p>Subtotal: $${subtotal.toFixed(2)}</p>
    <p>IVA (${this.taxRate}%): $${tax.toFixed(2)}</p>
    <p class="total-row">Total: $${sale.total.toFixed(2)}</p>
  </div>
  
  <div class="no-print" style="margin-top: 30px; text-align: center;">
    <button onclick="window.print()" style="padding: 10px 20px; font-size: 16px;">Imprimir</button>
    <button onclick="window.close()" style="padding: 10px 20px; font-size: 16px; margin-left: 10px;">Cerrar</button>
  </div>
</body>
</html>
    `

    const printWindow = window.open("", "_blank")
    printWindow.document.write(invoiceContent)
    printWindow.document.close()
  }

  showRecipes() {
    if (!this.userManager.hasPermission("admin")) {
      alert("No tiene permisos para acceder a esta sección")
      this.navigateTo("dashboard")
      return
    }

    this.securityManager.logUserActivity("VIEW_RECIPES", "Visualizó las recetas", {
      section: "recipes",
    })

    const recipesRows = this.recipes
      .map(
        (recipe) => `
        <tr>
          <td>
            <img src="${recipe.image || "/placeholder.svg?height=50&width=50"}" 
                 class="product-image" alt="${recipe.name}" 
                 onerror="this.src='/placeholder.svg?height=50&width=50'">
          </td>
          <td>${recipe.name}</td>
          <td>${recipe.description}</td>
          <td>${recipe.preparationTime} min</td>
          <td><span class="badge badge-info">${recipe.difficulty}</span></td>
          <td>
            <button class="btn btn-small btn-secondary" onclick="system.viewRecipe(${recipe.id})">Ver</button>
            <button class="btn btn-small btn-danger" onclick="system.deleteRecipe(${recipe.id})">Eliminar</button>
          </td>
        </tr>
      `,
      )
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Gestión de Recetas</h2>
          <button id="addRecipeBtn" class="btn btn-primary">Agregar Receta</button>
        </div>
        <div class="card-body">
          ${
            this.recipes.length === 0
              ? "<p>No hay recetas registradas. Agregue la primera receta.</p>"
              : `<table class="table">
                <thead>
                  <tr>
                    <th>Imagen</th>
                    <th>Nombre</th>
                    <th>Descripción</th>
                    <th>Tiempo</th>
                    <th>Dificultad</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  ${recipesRows}
                </tbody>
              </table>`
          }
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content

    const addRecipeBtn = document.getElementById("addRecipeBtn")
    if (addRecipeBtn) {
      addRecipeBtn.addEventListener("click", () => {
        this.showAddRecipeModal()
      })
    }
  }

  showAddRecipeModal() {
    this.showModal(
      "Agregar Receta",
      `<form id="addRecipeForm">
        <div class="form-group">
          <label for="recipeName">Nombre de la Receta:</label>
          <input type="text" id="recipeName" required>
        </div>
        <div class="form-group">
          <label for="recipeDescription">Descripción:</label>
          <textarea id="recipeDescription" rows="3"></textarea>
        </div>
        <div class="form-group">
          <label for="recipeImage">Imagen (URL):</label>
          <input type="url" id="recipeImage">
        </div>
        <div class="form-group">
          <label for="preparationTime">Tiempo de Preparación (minutos):</label>
          <input type="number" id="preparationTime" min="1" value="30">
        </div>
        <div class="form-group">
          <label for="difficulty">Dificultad:</label>
          <select id="difficulty">
            <option value="Fácil">Fácil</option>
            <option value="Media" selected>Media</option>
            <option value="Difícil">Difícil</option>
          </select>
        </div>
        <div class="form-group">
          <label for="recipeSteps">Pasos de Preparación:</label>
          <textarea id="recipeSteps" rows="6" placeholder="Escriba cada paso en una línea separada"></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Agregar Receta</button>
      </form>`,
    )

    document.getElementById("addRecipeForm").addEventListener("submit", (e) => {
      e.preventDefault()
      const name = this.securityManager.sanitizeInput(document.getElementById("recipeName").value)
      const description = this.securityManager.sanitizeInput(document.getElementById("recipeDescription").value)
      const image = this.securityManager.sanitizeInput(document.getElementById("recipeImage").value)
      const preparationTime = Number.parseInt(document.getElementById("preparationTime").value)
      const difficulty = document.getElementById("difficulty").value
      const stepsText = document.getElementById("recipeSteps").value
      const steps = stepsText.split("\n").filter((step) => step.trim() !== "")

      const newRecipe = new Recipe(Date.now(), name, description, [], steps, preparationTime, difficulty, image)
      this.recipes.push(newRecipe)
      this.saveData()

      this.securityManager.logUserActivity("RECIPE_CREATED", `Receta creada: ${name}`, {
        section: "recipes",
        difficulty: difficulty,
        preparationTime: preparationTime,
      })

      alert("Receta agregada exitosamente")
      this.closeModal()
      this.showRecipes()
    })
  }

  viewRecipe(id) {
    const recipe = this.recipes.find((r) => r.id === id)
    if (!recipe) return

    const stepsList = recipe.steps.map((step, index) => `<li>${index + 1}. ${step}</li>`).join("")

    this.showModal(
      recipe.name,
      `<div style="max-width: 600px;">
        ${recipe.image ? `<img src="${recipe.image}" alt="${recipe.name}" style="width: 100%; max-height: 300px; object-fit: cover; border-radius: 8px; margin-bottom: 1rem;">` : ""}
        <p><strong>Descripción:</strong> ${recipe.description}</p>
        <p><strong>Tiempo de Preparación:</strong> ${recipe.preparationTime} minutos</p>
        <p><strong>Dificultad:</strong> <span class="badge badge-info">${recipe.difficulty}</span></p>
        <h4>Pasos de Preparación:</h4>
        <ol style="padding-left: 20px;">
          ${stepsList}
        </ol>
        <p><small>Creada el: ${new Date(recipe.createdAt).toLocaleDateString()}</small></p>
      </div>`,
    )
  }

  deleteRecipe(id) {
    if (confirm("¿Está seguro de eliminar esta receta?")) {
      const recipe = this.recipes.find((r) => r.id === id)
      this.recipes = this.recipes.filter((r) => r.id !== id)
      this.saveData()

      this.securityManager.logUserActivity("RECIPE_DELETED", `Receta eliminada: ${recipe ? recipe.name : id}`, {
        section: "recipes",
      })

      alert("Receta eliminada exitosamente")
      this.showRecipes()
    }
  }

  showReports() {
    this.securityManager.logUserActivity("VIEW_REPORTS", "Visualizó los reportes", {
      section: "reports",
    })

    const totalSales = this.sales.reduce((sum, sale) => sum + (sale.total || 0), 0)
    const totalProducts = this.products.length
    const totalIngredients = this.ingredients.length

    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const tomorrow = new Date(today)
    tomorrow.setDate(today.getDate() + 1)

    const todaySales = this.sales.filter((sale) => {
      const saleDate = new Date(sale.date)
      return saleDate >= today && saleDate < tomorrow
    })

    const todayTotalSales = todaySales.reduce((sum, sale) => sum + (sale.total || 0), 0)
    const todayIVACollected = todaySales.reduce((sum, sale) => {
      const subtotal = sale.total / (1 + this.taxRate / 100)
      const iva = sale.total - subtotal
      return sum + iva
    }, 0)
    const todayGrossSales = todaySales.reduce((sum, sale) => {
      const subtotal = sale.total / (1 + this.taxRate / 100)
      return sum + subtotal
    }, 0)
    const todayInvestmentRecovery = todaySales.reduce((sum, sale) => {
      const product = this.products.find((p) => p.name === sale.productName)
      if (product && product.productionCost) {
        return sum + product.productionCost * sale.quantity
      }
      return sum
    }, 0)
    const todayNetProfit = todayGrossSales - todayInvestmentRecovery

    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = new Date(today)
      date.setDate(today.getDate() - i)
      return date
    }).reverse()

    const salesByDay = last7Days.map((date) => {
      const dayStart = new Date(date)
      dayStart.setHours(0, 0, 0, 0)
      const dayEnd = new Date(date)
      dayEnd.setHours(23, 59, 59, 999)

      const daySales = this.sales.filter((sale) => {
        const saleDate = new Date(sale.date)
        return saleDate >= dayStart && saleDate <= dayEnd
      })

      const dayTotal = daySales.reduce((sum, sale) => sum + (sale.total || 0), 0)

      return {
        date: date.toLocaleDateString(),
        count: daySales.length,
        total: dayTotal,
      }
    })

    const salesByDayRows = salesByDay
      .map(
        (day) => `
        <tr>
          <td>${day.date}</td>
          <td>${day.count}</td>
          <td>$${day.total.toFixed(2)}</td>
        </tr>
      `,
      )
      .join("")

    // Calcular top 3 vendedores
    const salesBySeller = {}
    this.sales.forEach((sale) => {
      const seller = sale.seller || "Sin vendedor"
      if (!salesBySeller[seller]) {
        salesBySeller[seller] = {
          totalSales: 0,
          totalAmount: 0,
          salesCount: 0,
        }
      }
      salesBySeller[seller].totalAmount += sale.total || 0
      salesBySeller[seller].salesCount += 1
      salesBySeller[seller].totalSales = salesBySeller[seller].totalAmount
    })

    const topSellers = Object.entries(salesBySeller)
      .sort(([, a], [, b]) => b.totalAmount - a.totalAmount)
      .slice(0, 3)
      .map(([seller, data], index) => ({
        position: index + 1,
        seller: seller,
        totalAmount: data.totalAmount,
        salesCount: data.salesCount,
        averagePerSale: data.salesCount > 0 ? data.totalAmount / data.salesCount : 0,
      }))

    const topSellersRows = topSellers
      .map((seller) => {
        let medalIcon = ""
        let positionClass = ""

        switch (seller.position) {
          case 1:
            medalIcon = "🥇"
            positionClass = 'style="background-color: #fff3cd; border-left: 4px solid #ffc107;"'
            break
          case 2:
            medalIcon = "🥈"
            positionClass = 'style="background-color: #e2e3e5; border-left: 4px solid #6c757d;"'
            break
          case 3:
            medalIcon = "🥉"
            positionClass = 'style="background-color: #f8d7da; border-left: 4px solid #dc3545;"'
            break
        }

        return `
        <tr ${positionClass}>
          <td style="text-align: center; font-size: 1.5rem;">${medalIcon}</td>
          <td><strong>${seller.seller}</strong></td>
          <td>$${seller.totalAmount.toFixed(2)}</td>
          <td>${seller.salesCount}</td>
          <td>$${seller.averagePerSale.toFixed(2)}</td>
        </tr>
      `
      })
      .join("")

    const content = `
      <div class="card">
        <div class="card-header">
          <h2 class="card-title">Reportes del Sistema</h2>
        </div>
        <div class="card-body">
          <div style="margin-bottom: 2rem;">
            <h3 style="color: #2c3e50; margin-bottom: 1rem;">📊 Resumen del Día - ${today.toLocaleDateString()}</h3>
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));">
              <div class="stat-card" style="border-left: 4px solid #e74c3c;">
                <div class="stat-number" style="color: #e74c3c;">$${todayTotalSales.toFixed(2)}</div>
                <div class="stat-label">💰 Total Vendido</div>
                <small style="color: #7f8c8d;">${todaySales.length} transacciones</small>
              </div>
              <div class="stat-card" style="border-left: 4px solid #f39c12;">
                <div class="stat-number" style="color: #f39c12;">$${todayIVACollected.toFixed(2)}</div>
                <div class="stat-label">🏛️ IVA Recaudado</div>
                <small style="color: #7f8c8d;">${this.taxRate}% de impuestos</small>
              </div>
              <div class="stat-card" style="border-left: 4px solid #27ae60;">
                <div class="stat-number" style="color: #27ae60;">$${todayGrossSales.toFixed(2)}</div>
                <div class="stat-label">📈 Monto Bruto (sin IVA)</div>
                <small style="color: #7f8c8d;">Ventas netas del día</small>
              </div>
              <div class="stat-card" style="border-left: 4px solid #3498db;">
                <div class="stat-number" style="color: #3498db;">$${todayInvestmentRecovery.toFixed(2)}</div>
                <div class="stat-label">🔄 Recuperación de Inversión</div>
                <small style="color: #7f8c8d;">Costos de producción recuperados</small>
              </div>
              <div class="stat-card" style="border-left: 4px solid #9b59b6;">
                <div class="stat-number" style="color: #9b59b6;">$${todayNetProfit.toFixed(2)}</div>
                <div class="stat-label">💎 Ganancia Neta</div>
                <small style="color: #7f8c8d;">Beneficio real del día</small>
              </div>
            </div>
          </div>

          <div style="margin-bottom: 2rem;">
            <h3 style="color: #2c3e50; margin-bottom: 1rem;">📋 Estadísticas Generales</h3>
            <div class="stats-grid">
              <div class="stat-card">
                <div class="stat-number">$${totalSales.toFixed(2)}</div>
                <div class="stat-label">Ventas Totales Históricas</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${totalProducts}</div>
                <div class="stat-label">Productos Activos</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${totalIngredients}</div>
                <div class="stat-label">Ingredientes</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${this.sales.length}</div>
                <div class="stat-label">Transacciones Totales</div>
              </div>
            </div>
          </div>

          <div style="margin-bottom: 2rem;">
            <h3 style="color: #2c3e50; margin-bottom: 1rem;">🏆 Top 3 Vendedores</h3>
            ${
              topSellers.length === 0
                ? '<p style="text-align: center; color: #6c757d; font-style: italic;">No hay datos de vendedores disponibles</p>'
                : `<table class="table" style="margin-bottom: 0;">
                <thead>
                  <tr>
                    <th style="text-align: center; width: 80px;">Posición</th>
                    <th>Vendedor</th>
                    <th>Total Vendido</th>
                    <th>Número de Ventas</th>
                    <th>Promedio por Venta</th>
                  </tr>
                </thead>
                <tbody>
                  ${topSellersRows}
                </tbody>
              </table>
              
              <div style="margin-top: 1rem; padding: 1rem; background-color: #f8f9fa; border-radius: 8px;">
                <h5 style="color: #2c3e50; margin-bottom: 0.5rem;">📊 Análisis de Rendimiento:</h5>
                <div class="grid grid-3" style="gap: 1rem;">
                  ${topSellers
                    .map(
                      (seller) => `
                    <div style="text-align: center; padding: 0.5rem;">
                      <div style="font-size: 1.2rem; margin-bottom: 0.25rem;">${seller.position === 1 ? "🥇" : seller.position === 2 ? "🥈" : "🥉"}</div>
                      <div style="font-weight: bold; color: #2c3e50;">${seller.seller}</div>
                      <div style="font-size: 0.9rem; color: #6c757d;">
                        ${((seller.totalAmount / topSellers[0].totalAmount) * 100).toFixed(1)}% del líder
                      </div>
                    </div>
                  `,
                    )
                    .join("")}
                </div>
                ${
                  topSellers.length > 0
                    ? `
                  <div style="margin-top: 1rem; text-align: center; font-size: 0.9rem; color: #6c757d;">
                    <strong>Diferencia entre 1° y 3°:</strong> $${(topSellers[0].totalAmount - (topSellers[2]?.totalAmount || 0)).toFixed(2)}
                    ${topSellers.length >= 2 ? ` | <strong>Brecha 1° vs 2°:</strong> $${(topSellers[0].totalAmount - topSellers[1].totalAmount).toFixed(2)}` : ""}
                  </div>
                `
                    : ""
                }
              </div>`
            }
          </div>

          <div style="margin-bottom: 2rem; padding: 1.5rem; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid #f1c40f;">
            <h4 style="color: #2c3e50; margin-bottom: 1rem;">💡 Análisis de Rentabilidad del Día</h4>
            <div class="grid grid-2">
              <div>
                <p><strong>Margen de Ganancia Bruta:</strong> ${todayGrossSales > 0 ? (((todayGrossSales - todayInvestmentRecovery) / todayGrossSales) * 100).toFixed(1) : 0}%</p>
                <p><strong>Eficiencia de Recuperación:</strong> ${todayTotalSales > 0 ? ((todayInvestmentRecovery / todayTotalSales) * 100).toFixed(1) : 0}%</p>
                <p><strong>Rentabilidad Neta:</strong> ${todayTotalSales > 0 ? ((todayNetProfit / todayTotalSales) * 100).toFixed(1) : 0}%</p>
              </div>
              <div>
                <p><strong>IVA vs Ventas Totales:</strong> ${todayTotalSales > 0 ? ((todayIVACollected / todayTotalSales) * 100).toFixed(1) : 0}%</p>
                <p><strong>Estado de Inversión:</strong> ${todayInvestmentRecovery > 0 ? "✅ Recuperando costos" : "⚠️ Sin recuperación"}</p>
                <p><strong>Rendimiento del Día:</strong> ${todayNetProfit > 0 ? "📈 Positivo" : todayNetProfit < 0 ? "📉 Negativo" : "➖ Neutro"}</p>
              </div>
            </div>
          </div>

          <div style="margin-top: 2rem;">
            <h3>📅 Ventas por Día (Últimos 7 días)</h3>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha</th>
                  <th>Ventas</th>
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                ${salesByDayRows}
              </tbody>
            </table>
          </div>

          <div style="margin-top: 2rem;">
            <h3>ℹ️ Resumen de Actividad</h3>
            <p>Sistema funcionando correctamente con ${this.userManager.users.length} usuarios registrados.</p>
            <p>Próximo número de factura: <strong>${this.invoiceManager.prefix}${(this.invoiceManager.getCurrentNumber() + 1).toString().padStart(8, "0")}</strong></p>
            <p>Última actualización: ${new Date().toLocaleString()}</p>
          </div>
        </div>
      </div>
    `

    document.getElementById("contentArea").innerHTML = content
  }
}

// Inicializar el sistema cuando se carga la página
let system
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM cargado, inicializando sistema...")
  system = new CharcuteriaSystem()
  window.system = system // Hacer disponible globalmente para los event handlers
})
const userManager = new UserManager(); // Instancia global (si no existe, crea una)

// Escucha los clics en botones de eliminar
document.addEventListener("click", function (e) {
  if (e.target.classList.contains("delete-user-btn")) {
    const username = e.target.getAttribute("data-username");
    const result = userManager.deleteUser(username);
    alert(result.message);
    if (result.success) {
      renderUserList();
    }
  }

  document.getElementById("addUserForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const username = document.getElementById("newUsername").value;
  const password = document.getElementById("newPassword").value;
  const role = document.getElementById("newRole").value;

  const result = userManager.addUser(username, password, role);
  alert(result.message);
  if (result.success) {
    renderUserList();
    e.target.reset();
    }
  });
});
