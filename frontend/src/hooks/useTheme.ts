import { useState, useEffect } from 'react'
import { create } from 'zustand'

interface ThemeStore {
  isDark: boolean
  toggleTheme: () => void
}

const useThemeStore = create<ThemeStore>((set) => ({
  isDark: localStorage.getItem('theme') === 'dark' || 
    (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches),
  toggleTheme: () => set((state) => {
    const newDark = !state.isDark
    localStorage.setItem('theme', newDark ? 'dark' : 'light')
    return { isDark: newDark }
  }),
}))

export const useTheme = () => useThemeStore()
