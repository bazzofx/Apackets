import AlertRulesSection from '@/components/AlertRulesSection'
import Page from '@/components/Page'
import { SECTIONS } from '@/theme/sections'

/**
 * Alert Settings: the two families of rule that decide what a capture flags.
 *
 * This was a section of the Settings page until the sidebar gave it a page of its
 * own. It belongs beside Settings rather than inside it because it is not
 * configuration in the same sense: Settings holds the knobs of this installation,
 * while these two tables are the detector itself — and reading them is how anyone
 * checks whether what shipped is what is running.
 */
export function AlertSettingsPage() {
  return (
    <Page section={SECTIONS.alertSettings}>
      <AlertRulesSection />
    </Page>
  )
}

export default AlertSettingsPage
