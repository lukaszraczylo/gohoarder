<template>
  <div class="min-h-screen bg-background">
    <nav class="sticky top-0 z-50 bg-card/95 backdrop-blur-lg shadow-sm border-b">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary text-primary-foreground">
              <i class="fas fa-box-open text-lg"></i>
            </div>
            <div class="flex flex-col">
              <h1 class="text-lg font-semibold tracking-tight text-foreground">GoHoarder</h1>
              <p class="text-xs text-muted-foreground">Package Cache Manager</p>
            </div>
          </div>
          <div class="flex items-center gap-1">
            <router-link
              to="/"
              class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-foreground/70 hover:text-foreground hover:bg-accent transition-colors"
              active-class="text-foreground bg-accent"
            >
              <i class="fas fa-chart-pie text-sm"></i>
              <span>Dashboard</span>
            </router-link>
            <router-link
              to="/packages"
              class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-foreground/70 hover:text-foreground hover:bg-accent transition-colors"
              active-class="text-foreground bg-accent"
            >
              <i class="fas fa-boxes text-sm"></i>
              <span>Packages</span>
            </router-link>
            <router-link
              to="/stats"
              class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-foreground/70 hover:text-foreground hover:bg-accent transition-colors"
              active-class="text-foreground bg-accent"
            >
              <i class="fas fa-chart-bar text-sm"></i>
              <span>Statistics</span>
            </router-link>
            <router-link
              to="/admin/bypasses"
              class="inline-flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium text-foreground/70 hover:text-foreground hover:bg-accent transition-colors"
              active-class="text-foreground bg-accent"
            >
              <i class="fas fa-shield-alt text-sm"></i>
              <span>Admin</span>
            </router-link>
          </div>
        </div>
      </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
// App component
</script>
